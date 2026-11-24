# F-05: Authentication Bypass via Deprecated API Version — Full Account Impersonation (Including Superadmin)

- **CWE:** CWE-287 (Improper Authentication) + CWE-862 (Missing Authorization)
- **OWASP:** A01:2021 Broken Access Control / A07:2021 Identification and Authentication Failures
- **Endpoint:** `POST /api/v1/ops/impersonate`
- **Severity:** Critical
- **CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` — 9.9

## Summary

Found via JS recon on the app's frontend bundle, which referenced an `/ops/impersonate` endpoint not used anywhere in the normal UI. Testing showed the current API version (`v2`) doesn't expose this route, but the **old `v1` version is still live in production** and accepts it with no role check at all — any authenticated user, regardless of role, can request a valid signed token for *any other user ID*, including a `superadmin` account.

## Steps to Reproduce

1. `GET /api/v2/ops/impersonate` → `404 Route not found`
2. `GET /api/v1/ops/impersonate` → `404 Route not found` (GET not supported)
3. `POST /api/v1/ops/impersonate` with no body, authenticated as my own low-privilege patient account:
   ```http
   POST /api/v1/ops/impersonate HTTP/1.1
   Authorization: Bearer <redacted — patient token>
   ```
   Response: `400 Bad Request`, `{"error":"userId required"}` — confirms the endpoint exists, accepts POST, and only validates that a parameter is present, not whether the caller is authorized to use it at all.

4. `POST /api/v1/ops/impersonate` with `{"userId": 10000}`, same patient token:
   ```http
   POST /api/v1/ops/impersonate HTTP/1.1
   Authorization: Bearer <redacted — patient token>
   Content-Type: application/json

   {"userId": 10000}
   ```
   Response: `200 OK`, returning a **full, valid JWT** for a different account entirely:
   ```json
   {
     "token": "<redacted — valid superadmin token>",
     "user": {
       "id": 10000,
       "email": "platform-admin@medconnect.io",
       "role": "superadmin",
       "orgId": "a3f8c2d1-...",
       "_legacy": true
     }
   }
   ```

5. Confirmed `userId` isn't scoped to any role check at all — `userId: 10010` separately resolved to a real doctor account with no special access needed to query it either.

## Impact

Complete compromise of the application. A patient account — the lowest-privilege role in the system — can escalate to `superadmin` by calling a single deprecated endpoint with an arbitrary user ID. The returned token grants full administrative control over the entire platform, not just one organization. The `_legacy: true` field in the response strongly suggests this is leftover functionality from an API migration that was never removed or locked down.

## Root Cause

The `v2` API either removed or never implemented this route (`404`), but the `v1` route was left live in production with **no authorization check whatsoever** — not even a role check, let alone an ownership check. Any authenticated user, of any role, can call it and receive a signed token for any `userId` in the system.

## Why Scope Is "Changed" in the CVSS Vector

Exploiting this low-privilege endpoint grants control over a security authority (a superadmin identity) entirely outside the vulnerable component's own boundary — the impact isn't contained to "this endpoint returns bad data," it's "this endpoint hands you the keys to the whole system." That's what justifies `S:C` and the resulting 9.9 score.

## Remediation

- Immediately disable or remove the `v1` impersonation route; if impersonation is a legitimate admin feature, it must only exist in the current API version with a strict role check (`current_user.role == 'admin'` or similar) before it does anything else.
- Audit all other `v1` routes for the same issue — if one deprecated endpoint was left live with no auth, others likely were too.
- Add a process step to API version deprecation: confirm old routes are fully decommissioned (return `404`/`410` for all methods), not just removed from the current version's routing table.
- Add logging/alerting on any successful call to an impersonation-style endpoint, since legitimate use of this feature (if any) should be rare and auditable.

## Evidence

![v2 returns 404](../screenshots/f05/01-v2-404.png)
![v1 GET also 404](../screenshots/f05/02-v1-get-404.png)
![v1 POST with no body - userId required](../screenshots/f05/03-userid-required.png)
![v1 POST with userId:10000 - superadmin token returned](../screenshots/f05/04-superadmin-token.png)
![Confirming userId:10010 resolves to a real doctor account](../screenshots/f05/05-doctor-confirmation.png)
