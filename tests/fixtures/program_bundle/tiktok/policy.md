# TikTok Bug Bounty Program Policy

## Program Overview

TikTok is a destination for short-form mobile videos. Our mission is to capture and present the world's creativity, knowledge, and moments that matter in everyday life.

## Scopes

### In Scope

All TikTok web properties marked as in-scope in our HackerOne scope table.

### Exclusion

The following are temporarily excluded from the program:
- `https://developers.tiktok.com/minis/` — from 2026-02-22 until further notice
- TikTok FBT platform — from 2026-05-13 23:59 GMT+8 until further notice

## Prohibited Activities

### Social Engineering
Social engineering activities including phishing, vishing, or any form of human interaction to gain unauthorized access are strictly prohibited.

### Denial of Service
DoS, DDoS, and service disruption testing are not allowed under any circumstances.

### Privacy Violations
Accessing, downloading, or using user data beyond what is necessary to demonstrate a vulnerability is prohibited. Do not access personal information.

### Post-Exploitation
If you gain access to internal resources, stop there and report immediately. Do not move laterally, pivot, or attempt further exploitation.

## SSRF Testing

SSRF testing is permitted but ONLY against the following destinations:
- `https://ssrf-bait.byted.org/full-read-ssrf`
- `https://ssrf-bait.byted.org/blind-ssrf/*`

Do not test SSRF against any other internal or external destination.

## Test Accounts

Test accounts are available upon request. Do not test on production accounts of other users.

## Reporting

Submit reports with clear steps to reproduce. Include impact assessment.

## Safe Harbor

Activities conducted in accordance with this policy are considered authorized. We will not pursue legal action.
