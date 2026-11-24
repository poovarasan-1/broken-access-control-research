# T-04: Cross-Tenant Write — Posting Comments Onto Another Org's Task

- **CWE:** CWE-639 (IDOR) — write-side
- **OWASP:** A01:2021 Broken Access Control
- **Endpoint:** `POST /api/tasks/{id}/comments`
- **Severity:** High
- **CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N` — 7.7

## Summary

T-01 proved this app's task endpoints have no tenant-scope check on **read**. This finding proves the exact same missing check exists on **write** — I was able to post a comment, under my own real identity, directly onto another organization's task. This elevates the issue from "information disclosure" to "cross-tenant data integrity compromise": an outside-org user can inject arbitrary content into another organization's internal records.

## Steps to Reproduce

1. Used task `id: 17`, known (from earlier testing) to belong to the other org.
2. Posted a comment to it while authenticated as my own account (org 1 — "Acme"):
   ```http
   POST /api/tasks/17/comments HTTP/1.1
   Authorization: Bearer <redacted — my own, org-1 token>
   Content-Type: application/json

   {"content": "new comments by outer user"}
   ```
3. Response (200 OK) confirmed the comment was created and persisted:
   ```json
   { "id": 33, "user_id": 1, "user_name": "Alice Johnson", "user_email": "alice@acme.com",
     "content": "new comments by outer user", "created_at": "2026-11-18 09:34:18" }
   ```
4. Verified persistence by re-fetching the task's export (per T-03) and confirming the comment now appears permanently in **Globex's (org 2) data**, visible to that org's own users (Charlie Brown, Diana Prince).

## Impact

A user from Org A can inject arbitrary content into Org B's internal records, under their own real name and email — this is directly attributable, not anonymous, which in a real engagement could be used for planting misleading instructions, phishing links, or malicious content inside another company's internal task tracker, convincingly attributed since it shows the actual poster's identity. This is a cross-tenant **integrity** compromise, not just confidentiality, and in a real engagement this class of finding typically gets escalated immediately.

## Root Cause

The comment-creation endpoint has the exact same missing tenant-scope check as the read-side task lookup (T-01) — it validates that the task ID exists, not that it belongs to the caller's organization, and applies no check on write any more than it does on read.

## Remediation

- Apply the identical fix as T-01/T-02/T-03 to this endpoint: scope the task lookup used for comment creation by `org_id`, not just `id`.
- This finding is good evidence that fixing a BAC issue only on read-paths and assuming write-paths are safe is a mistake — every endpoint touching a tenant-scoped resource needs the same check, independent of HTTP method.
- Add integration tests that specifically attempt cross-org writes (not just cross-org reads) for every mutating endpoint.

## Evidence

![POST request creating a comment on another org's task](../screenshots/t04/01-post-comment-cross-org.png)
![Comment persisted and visible in the victim org's export](../screenshots/t04/02-comment-in-victim-export.png)
