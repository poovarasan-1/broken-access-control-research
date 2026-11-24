# T-05: Broken Function-Level Authorization on Invite Acceptance

- **CWE:** CWE-862 (Missing Authorization) — function-level check missing, combined with a missing object-identity check
- **OWASP:** A01:2021 Broken Access Control
- **Endpoint:** `POST /api/invites/{id}/accept`
- **Severity:** High
- **CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` — 5.9 (see note below on why practical severity is higher)

## Summary

This finding went through a correction while I was testing it, and I'm keeping that in the write-up because it's the most instructive part.

I initially found that `POST /api/invites/INV-0002/accept` succeeded and bound a pending invite — for a project under **my own organization** — to my account, with no role check and no check that I was the invite's intended recipient. My first instinct was to call this "cross-tenant takeover." **That was wrong.** After checking the invite's actual project (`proj-acme-mobile-app-002`, confirmed as an Acme/org-1 project — my own org), I realized this wasn't a cross-tenant bug at all. The real finding is **same-org Broken Function-Level Authorization**: any authenticated user in the org, regardless of role, can accept any pending invite in that org — not just invites meant for them.

## Steps to Reproduce

```http
POST /api/invites/INV-0002/accept HTTP/1.1
Authorization: Bearer <redacted — my own account, no special invite/admin role>
```

Response (200 OK):
```json
{"message":"Invite accepted successfully","project_uuid":"proj-acme-mobile-app-002",
"role":"member","flag":"FLAG{invite_hijack_no_email_check}"}
```

Invite IDs are sequential (`INV-0001`, `INV-0002`, ...), not cryptographically random — they didn't require a leak to find, just direct enumeration.

## What's Actually Happening

Two independent missing checks are stacked on this single endpoint:

1. **No role/function-level check:** accepting an invite is normally an action that should require being the specific invited person, or at minimum holding an admin/inviter role. The endpoint only checks "am I authenticated," not "am I allowed to perform this specific action."
2. **No recipient-identity check:** the invite was created with a specific intended recipient (an email address). The backend never verifies that the accepting identity matches that target — which is exactly what the flag name (`no_email_check`) confirms.

## Impact

Any authenticated low-privilege user within their own org can self-assign membership and a role to any project by hijacking someone else's pending invite — without ever being invited themselves. This is a same-org, intra-tenant vertical/lateral privilege escalation primitive. Severity would be substantially higher if any pending invite in the org carried an `admin` role rather than `member` — that would make this a clean low-privilege-user-to-org-admin escalation; this specific PoC used a `member`-role invite, so the demonstrated impact is unauthorized project membership rather than confirmed admin takeover.

## Why the CVSS Base Score Understates This

The base vector (5.9) reflects a single unauthorized membership grant. The real risk is structural: **two separate authorization checks are missing on the same endpoint at once** — a stronger signal of a systemic gap than either check being missing alone. In a real engagement, this would likely be reported at a higher practical severity than the raw CVSS math suggests, with a note explaining why (same approach taken in Assessment 01's F-04).

## Root Cause

The invite-acceptance endpoint validates only that the invite ID exists and is in a "pending" state. It checks neither the caller's role/permission to perform the accept action, nor that the caller's identity (email) matches the invite's intended recipient.

## Remediation

- Require that the accepting user's authenticated email matches the invite's target email before allowing acceptance.
- Additionally restrict who can call this endpoint at all — if self-acceptance by the invited person is the only legitimate flow, no other authenticated user should reach this action successfully, regardless of org membership.
- Replace sequential invite IDs (`INV-0001`, `INV-0002`...) with non-guessable tokens, as defense in depth — though this should never be relied on as the only protection, per the lesson from T-03.

## Evidence

![Invite accept succeeding with no role or identity check](../screenshots/t05/01-invite-accept-success.png)
![Confirming the invite's project belongs to my own org, not a different tenant](../screenshots/t05/02-confirming-same-org.png)
