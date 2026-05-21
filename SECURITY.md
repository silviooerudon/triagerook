# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities privately via GitHub Security Advisories.

1. Go to the Security tab of this repository
2. Click "Report a vulnerability"
3. Or visit: ../../security/advisories/new

You can expect:
- Acknowledgement within 72 hours
- Initial assessment within 7 days
- Coordination on disclosure timing

Please do not open public issues for security vulnerabilities or disclose them publicly before we have had a chance to address them.

## Scope

In scope: the TriageRook web app (https://repoguard-chi.vercel.app), source code in this repository, authentication and session handling, scan execution and result persistence.

Out of scope: physical access attacks, social engineering, denial of service from unrealistic load, vulnerabilities in upstream services (GitHub, Vercel, Supabase, npm, OSV) - please report those to the respective vendors.

## Supported Versions

TriageRook is in active beta. Only the latest deployed version is supported.