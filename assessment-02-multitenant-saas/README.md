# Assessment 02 — Multi-Tenant SaaS (Capstone Challenge)

A project/task management SaaS app, tested as the final capstone challenge for my Broken Access Control course. Two organizations ("Acme" and "Globex"), multiple users and roles, tested manually in Caido.

## Target

A multi-tenant project/task management API — projects, tasks, comments, an activity feed, and invite-based team membership, split across at least two separate organizations.

## Methodology

1. Set up test accounts across two different orgs to test both horizontal (cross-user) and cross-tenant (cross-org) access.
2. Mapped every endpoint that takes an object ID — tasks, projects, invites, activity entries.
3. For each one, replayed requests from my own account against the other org's known/guessed IDs.
4. Tested read access first, then wrote back to the same endpoints to check whether write access was equally unprotected.
5. Used an initial info-leak (an unscoped activity feed) to obtain UUIDs for a later endpoint that otherwise looked protected by "unguessable" UUIDs.

## Findings

| ID | Title | Severity | CWE |
|---|---|---|---|
| [T-01](./findings/T-01-task-bola.md) | Cross-tenant BOLA on task lookup | Medium (6.5) | CWE-639 |
| [T-02](./findings/T-02-activity-feed-leak.md) | Unscoped activity feed — cross-org data and UUID leak | High | CWE-639 |
| [T-03](./findings/T-03-export-uuid-idor.md) | UUID-based IDOR on project export, exploited via T-02's leaked UUIDs | High | CWE-639 |
| [T-04](./findings/T-04-comment-write-injection.md) | Cross-tenant write — posting comments onto another org's task | High | CWE-639 |
| [T-05](./findings/T-05-invite-accept-bfla.md) | Unauthorized invitation acceptance — missing recipient identity verification | High (7.7) | CWE-862 |


T-02 → T-03 is the most instructive chain in this assessment: it demonstrates that UUID-based resource IDs are not a substitute for proper authorization checks — they only raise the bar to guessing, and this app leaked the UUIDs elsewhere anyway, fully defeating that protection.

## A note on getting something wrong

While testing T-05, I initially classified it as a cross-tenant takeover. After checking my own `org_id`, I realized the invite actually belonged to my own organization — so the real bug wasn't tenant isolation, it was a same-org permission failure (BFLA) stacked with a missing identity check on who's allowed to accept an invite. I kept that correction in T-05's write-up instead of cleaning it up, since catching it was part of doing the testing properly.

## Evidence

Screenshots for each finding are in [`screenshots/`](./screenshots), organized by finding ID. All tokens, cookies, and flags are redacted.

## Tools

Caido (HTTP History, Replay, Automate)
