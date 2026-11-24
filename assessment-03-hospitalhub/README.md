# Assessment 03 — HospitalHub

A hospital staff/patient portal, tested as part of the same BAC course. This is my strongest assessment of the three — it includes a full, demonstrated account takeover, not just information disclosure.

## Target

A hospital management portal ("HospitalHub") with staff profiles, patient search, clinical records, and role-based dashboards (physician, chief of medicine, admin), spanning multiple clinics/hospitals.

## Methodology

1. Logged in as a normal physician-level account and captured baseline requests for my own profile.
2. Noticed the profile endpoint embedded the full backend user object into the page's JS (`window.__INIT_PROFILE__`), including fields that should never reach any client.
3. Tested whether the same endpoint leaked other users' data by changing the numeric ID — found a clinic-level boundary check, but no user-level one.
4. Noticed the session cookie was a small sequential integer and fuzzed it directly, which bypassed the clinic boundary entirely (since it operates at the authentication layer, not the application layer).
5. Used a harvested session to log in as a higher-privileged account and confirmed real administrative access.
6. Separately tested a patient-search endpoint and a clinical-record-view endpoint for the same class of parameter-based IDOR.

## Findings

| ID | Title | Severity | CWE |
|---|---|---|---|
| [S-01](./findings/S-01-session-takeover.md) | Predictable session tokens → full account takeover (confirmed: Chief of Medicine, admin panel) | **Critical (9.9)** | CWE-330, CWE-287 |
| [H-01](./findings/H-01-profile-idor-credential-exposure.md) | IDOR + sensitive credential exposure on staff profile endpoint | **Critical (9.9)** | CWE-639, CWE-213 |
| [H-02](./findings/H-02-clinic-search-idor.md) | IDOR on `clinic_id` parameter — cross-hospital patient data | High (8.7) | CWE-639 |
| [H-03](./findings/H-03-record-id-idor.md) | IDOR on `record_id` parameter — clinical/diagnostic record disclosure | High (7.1) | CWE-639 |

S-01 is the headline finding across my entire portfolio: starting from a low-privilege account, I confirmed full login as the Chief of Medicine and reached a working admin panel — not a theoretical impact, a demonstrated one.

## Evidence

Screenshots for each finding are in [`screenshots/`](./screenshots), organized by finding ID. All credentials, tokens, session values, and flags are redacted.

## Tools

Caido (HTTP History, Replay, Automate, HTTPQL filtering)
