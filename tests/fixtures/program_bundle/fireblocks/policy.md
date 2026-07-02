# Fireblocks Bug Bounty Program Policy

## Program Overview

Fireblocks is an enterprise-grade platform for digital asset operations.

## Targets

- `sb-console-api.fireblocks.io`
- `sb-mobile-api.fireblocks.io`
- `sandbox-api.fireblocks.io`

Only the above-listed sandbox targets are in scope. Any other Fireblocks domain or property is out of scope.

## Focus Areas

The following areas are of particular interest:
- Authentication and authorization flaws
- API security issues
- Business logic vulnerabilities
- Injection vulnerabilities (SQL, NoSQL, command injection)
- Cryptographic implementation issues

## Excluded Submission Types

- `DoS/DDoS/Network DoS`
- `Rate limiting bypass attempts`
- Clickjacking on pages with no sensitive actions
- Self-XSS
- Social engineering attacks
- Missing HTTP security headers (without demonstrated impact)
- P5 vulnerabilities

## Out of Scope

- Any Fireblocks property not listed in Targets
- Third party providers and services
- Infrastructure-level attacks

## Post-Exploitation

Potential post-exploitation scenarios: if you gain access beyond the initial vulnerability, stop testing and submit your report immediately. Do not attempt lateral movement or further exploitation.

## Credentials

Test accounts are required. Please register using an email address from the `@bugcrowdninja.com` domain.

## N-day / Third Party 0-day Policy

N-day vulnerabilities in third party libraries are in scope if disclosed more than 14 days ago.

## Safe Harbor

Fireblocks will not pursue legal action against researchers who comply with this policy. We believe in coordinated disclosure.
