# Security Policy — Log Analyzer

## Supported version and confidential reporting
Security fixes target the default branch. Report vulnerabilities privately through GitHub private vulnerability reporting when available or contact the maintainer privately. Do not attach live authentication logs, tokens, usernames or public exploit details.

## Project-specific controls
- **GRC / privacy:** Authentication logs contain account names, source IPs, device identifiers and security events. Follow applicable data-retention and disclosure rules; anonymize test fixtures and published examples.
- **IAM:** Read system logs using the minimum OS privileges required. This tool must not alter accounts or credentials and must not collect passwords or reusable authentication tokens.
- **Data integrity:** Keep analysis read-only. Validate log paths and exports, protect output permissions, and handle untrusted log content as data rather than executable code.
- **Cloud:** No cloud service is required for this local analyzer. If centralized logging is added, require encrypted transport, scoped credentials, access auditing, retention and tenant separation.
- **AI:** If an AI summarizer is introduced, strip secrets and personal data, treat log text as untrusted input (including prompt-injection attempts), and require human review for incident actions.
- **OT:** Not currently within scope; industrial logs require a dedicated operational safety assessment.

## Release gate
Run ShellCheck, PowerShell analysis and smoke tests. Verify correct alert thresholds, safe parsing of malicious log lines, no unintended writes to source logs and no secrets in fixtures.
