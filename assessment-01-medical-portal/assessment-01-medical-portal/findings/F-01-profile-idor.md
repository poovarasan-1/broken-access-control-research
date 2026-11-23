# F-01: IDOR on Profile Endpoint — Cross-Role, Cross-Organization Data Disclosure

- **CWE:** CWE-639 (Insecure Direct Object Reference)
- **OWASP:** A01:2021 Broken Access Control
- **Endpoint:** `GET /api/medical/profile/{id}`
- **Severity:** Medium
- **CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` — 6.5

## Summary

The profile endpoint returns a full user record based solely on the numeric `id` in the path, with no check that the requesting user owns that profile. Any authenticated patient account can enumerate IDs and read other users' records — including staff, and users in different organizations entirely.

## Environment

- My account: `id 10001`, role `patient`, `org_id a3f8c2d1-...`
- Tool: Caido (HTTP History + Replay)

## Steps to Reproduce

1. Load my own profile, which calls:
   ```http
   GET /api/medical/profile/me HTTP/1.1
   Authorization: Bearer <redacted>
   ```
   Response (200 OK):
   ```json
   {"id":10001,"first_name":"John","last_name":"Doe","email":"patient1@sunrise.med",
   "role":"patient","org_id":"a3f8c2d1-7b4e-4a91-bc03-9d1f6e8a5c20","status":"active", ...}
   ```

2. Replayed the request with the path changed to a numeric ID one higher:
   ```http
   GET /api/medical/profile/10002 HTTP/1.1
   ```
   Response (200 OK) — a different person's full record, with a **different role** and **different org_id**:
   ```json
   {"id":10002,"first_name":"Olivia","last_name":"Carney","email":"olivia.carney@med1505.com",
   "role":"nurse","org_id":"e7b2a4f9-1c3d-4e5f-8a6b-2d9c0e7f1a3b","status":"active", ...}
   ```

3. Iterated IDs from `10002` to `10100` and recorded every `200 OK`: **72 of 99 requests** returned valid records belonging to other users, spanning multiple roles (`patient`, `nurse`) and multiple `org_id` values.

## Impact

An authenticated low-privilege patient account can read full profile records — name, email, role, organization, and account status — for dozens of other accounts, including hospital staff, with no authorization check and no rate limiting observed. Because `org_id` differs across leaked records, this also breaks organization-level isolation, not just per-user isolation — a patient registered under one organization can read full staff/patient records belonging to an entirely different organization.

## Root Cause

`GET /api/medical/profile/{id}` authenticates the request (a valid bearer token is required) but never checks that `{id}` belongs to the caller or the caller's organization. The `/me` alias likely resolves to the caller's own ID internally, but the numeric-ID route performs the identical lookup without that check.

## Remediation

- On every request to this endpoint, verify `id == current_user.id`, or that the caller holds an explicit role/permission to view other profiles within the same `org_id`.
- Scope the underlying query by `org_id` in addition to `id`, since this flaw crosses organizational boundaries.
- Return `403`/`404` on mismatch instead of the record.
- Add automated tests asserting one account can never retrieve another account's record, within or across organizations.
- Add rate limiting or anomaly detection on sequential-ID access patterns.

## Evidence

![Baseline request — own profile via /me](../screenshots/f01/01-baseline-me.png)
![IDOR — numeric ID returns another user's record](../screenshots/f01/02-idor-10002.png)
