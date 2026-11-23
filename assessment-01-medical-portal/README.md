# Broken Access Control Research

This repo has my practical work on Broken Access Control — IDOR, BOLA, BFLA, mass assignment, auth bypass, that whole family of bugs. I'm learning web/API security on my own and preparing for junior pentester / VAPT roles, so instead of just doing write-ups from theory I wanted a place where I actually test apps, break them, and document it properly like a real finding.

## Why BAC specifically

Broken Access Control is OWASP's #1 category for a reason — it shows up in almost every real app, and the root cause is usually simple once you find it (a missing ownership check, a missing role check, a missing function-level check). I picked it as my first focus area because it's testable without needing deep exploit-dev skills, and I can chain small findings into bigger ones, which is good practice for actual pentest reporting.

## What's inside

Each folder below is a separate assessment — a different target, tested independently, with its own findings and evidence.

| Assessment | Target | What it covers |
|---|---|---|
| [01 — Medical Portal](./assessment-01-medical-portal) | Patient/appointment management API | IDOR across patients and appointments, cross-org data leakage, role escalation via mass assignment, and a critical auth bypass through a deprecated API version leading to full account impersonation |
| [02 — Multi-Tenant SaaS](./assessment-02-multitenant-saas) | Project/task management app (capstone challenge for my BAC course) | Chained BOLA across tenants, UUID-based IDOR defeated via an earlier info leak, cross-tenant write/injection, and a BFLA on invite acceptance |
| [03 — HospitalHub](./assessment-03-hospitalhub) | Hospital staff/patient portal | Predictable session tokens leading to full account takeover (confirmed: logged in as the Chief of Medicine and reached the admin panel), plus stacked IDOR across staff profiles, clinics, and clinical records |

More will get added as I keep testing.

## How I test

Mostly manual, no heavy tooling yet:

1. Create two (sometimes three) test accounts with different roles and, where relevant, different orgs/clinics.
2. Walk through the app normally first, capturing my own requests in Caido so I know what "normal" looks like.
3. Once I know my own IDs/role/session, I start changing things — swap a user ID, swap an org/clinic ID, swap a role field, try a different HTTP method on the same endpoint.
4. If something unexpected comes back, I dig into *why* — which check is actually missing, not just "it worked."
5. Where it makes sense, I use Caido's Automate feature to sweep a range of IDs and its HTTPQL filter to find the interesting response out of a hundred, instead of reading every one by hand.
6. Write it up properly: request, response, root cause, impact, how I'd fix it — and I keep my mistakes in the write-up too (see note below).

## Tools

- Caido — main tool, HTTP history, Replay, and Automate
- Burp Suite — sometimes, for comparison
- Browser dev tools — quick checks

## A note on how I write these up

I try to be honest in these reports, including when I get something wrong. In Assessment 02, I initially called one finding a cross-tenant bug, and it turned out to actually be a same-org permission issue once I checked my own org ID — I left that correction in the write-up instead of cleaning it up, because catching your own mistake is part of doing this properly. Same idea applies across all three assessments: if a finding's severity or classification changed as I tested further, the write-up shows that progression, not just the final answer.

## Disclaimer

All of this was tested against intentionally vulnerable labs and training environments where testing is explicitly authorized (course-provided labs and a BAC course capstone project). Nothing here was tested against a real, non-consenting target. Flags and internal tokens from these labs are redacted in all evidence, since they're lab-specific artifacts, not something meant to be public. Don't use anything in here against a system you don't have permission to test.

## About me

I'm Poo, self-studying towards a junior pentester / VAPT role. This repo is part of my practice and portfolio while I build experience without formal work history yet.
