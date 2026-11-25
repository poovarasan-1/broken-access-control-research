# Assessment 01 — Medical Portal (MedConnect)

Patient/appointment management API tested for Broken Access Control issues. Two patient accounts, manual testing in Caido, no scripting — just changing IDs, roles, and HTTP methods and watching what the server lets through.

## Target

A hospital-style patient portal API (branded "MedConnect" in responses) with patients, appointments, and staff roles (patient, nurse, doctor, superadmin). Tested via a course-provided lab.

## Methodology

1. Logged in as a normal patient account and captured baseline requests for my own profile and appointments.
2. Changed numeric IDs in those requests to see if other patients'/staff's data came back.
3. Once IDOR was confirmed on reads, tested whether the same endpoints also accepted writes (PUT) with no extra checks.
4. Did basic JS recon on the app's frontend bundle and found an endpoint (`/ops/impersonate`) not used anywhere in the normal UI flow.
5. Tried mass assignment — sending extra/different fields in a profile update to see if the server trusted them blindly.

## Findings

| ID | Title | Severity | CWE |
|---|---|---|---|
| [F-01](./findings/F-01-profile-idor.md) | IDOR on patient/staff profile endpoint (cross-role, cross-org) | Medium (6.5) | CWE-639 |
| [F-02](./findings/F-02-appointment-idor.md) | IDOR on appointment read endpoint | Medium (6.5) | CWE-639 |
| [F-03](./findings/F-03-appointment-write-own.md) | Broken function-level access control — patient can set clinical appointment status | Medium (5.9) | CWE-285 |
| [F-04](./findings/F-04-chained-cross-patient-write.md) | Chained IDOR + BFLAC — modify another patient's appointment record | High (practical) | CWE-639, CWE-285 |
| [F-05](./findings/F-05-impersonation-authbypass.md) | Auth bypass via deprecated API version — full account impersonation (superadmin) | **Critical (9.9)** | CWE-287, CWE-862 |
| [F-06](./findings/F-06-mass-assignment-role.md) | Mass assignment on `role` field — self-service privilege escalation | High (8.8) | CWE-915 |

F-05 is the headline finding of this assessment: a low-privilege patient account escalating, through a version-downgrade on an internal API route, to a usable superadmin session.

## Evidence

Screenshots for each finding are in [`Screenshots/`](./screenshots), organized by finding ID. All tokens, cookies, and lab flags are redacted.

## Tools

Caido (HTTP History, Replay)
