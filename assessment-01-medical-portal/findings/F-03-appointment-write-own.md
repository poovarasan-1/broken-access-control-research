# F-03: Broken Function-Level Access Control — Patient Can Set Clinical Appointment Status

- **CWE:** CWE-285 (Improper Authorization)
- **OWASP:** A01:2021 Broken Access Control
- **Endpoint:** `PUT /api/medical/appointments/{id}`
- **Severity:** Medium
- **CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` — 5.9

## Summary

The appointment endpoint accepts a `PUT` request from a patient account and allows it to change the appointment's `status` field — a field that reflects a clinical/administrative outcome (e.g. `completed`, `cancelled`) and should only be writable by a doctor or admin role, not the patient themselves.

## Steps to Reproduce

Starting from my own appointment (`id 48`, `patient_id 10001`, my own account):

```http
PUT /api/medical/appointments/48 HTTP/1.1
Host: 7kpz980v0s22.ctfhub.io
Authorization: Bearer <redacted>
Content-Type: application/json

{"id":48,"patient_id":10001,"doctor_id":10010,"date":"2026-05-23","time":"09:30",
"status":"completed","reason":"Follow-up visit","doctor_notes":null,
"confirmation_code":"CONF-2025-0013","org_id":"a3f8c2d1-...","created_at":"2026-04-07 00:18:55"}
```

Response (200 OK): the appointment's `status` field was successfully changed from `cancelled` to `completed`, confirmed by re-fetching the record afterward.

## Additional Observation: Partial Body Accepted

In a later test on a different appointment (see F-04), sending **only** `{"status":"cancelled"}` — not the full object — also succeeded. This means the endpoint doesn't enforce PUT's usual "full resource replace" semantics and skips required-field validation entirely, independent of the authorization issue. Worth noting since it suggests the backend applies no schema validation on this write path at all.

## Impact

A patient account — which should only be able to view its own appointments, not alter their clinical status — can mark an appointment as completed, cancelled, or any other value the `status` field accepts. In a real clinical setting this could affect billing, insurance claims, and the accuracy of a patient's treatment history.

## Root Cause

The write path for this endpoint checks only that the caller is authenticated and that they are modifying their *own* record (if even that — see F-04 for proof that check is also missing). It does not check that the caller's **role** is permitted to modify the `status` field specifically — a function/field-level permission that should be restricted to doctor/admin roles.

## Remediation

- Add a role check specifically for clinically significant fields (`status`, `doctor_notes`): only `doctor` or `admin` roles should be able to set them.
- Consider splitting the endpoint into a patient-facing update (name, contact info) and a clinical-staff-only update (status, notes), rather than one shared PUT accepting any field.
- Add schema/field-level validation so arbitrary or partial bodies can't silently modify fields they shouldn't touch.

## Evidence

![PUT request changing status on own appointment](../screenshots/f03/01-put-own-status-change.png)
![Response confirming status changed to completed](../screenshots/f03/02-response-completed.png)
