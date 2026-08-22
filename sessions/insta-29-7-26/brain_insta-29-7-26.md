# Audit Brain: insta-29-7-26

## Session Overview
- **Target**: https://app.indiapost.gov.in/
- **Created**: 2026-07-29T13:13:59.819180562Z
- **Status**: Active (48 runs, 0 succeeded)

## Findings Summary

- **V-001** (Sensitive data via OSINT): fail — grep_absent -> FAIL
- **V-002** (Sub-domain enumeration): pass — grep_absent -> PASS
- **V-003** (Open port/unnecessary service): manual_review — grep_absent -> MANUAL_REVIEW
- **V-004** (DNS spoofing): pass — exit_code_zero -> PASS
- **V-005** (Banner grabbing/fingerprinting): pass — grep_absent -> PASS
- **V-006** (Weak TLS/SSL version): manual_review — grep_absent -> MANUAL_REVIEW
- **V-007** (Weak cipher suite): manual_review — grep_absent -> MANUAL_REVIEW
- **V-008** (Expired/self-signed certificate): manual_review — grep_absent -> MANUAL_REVIEW
- **V-010** (Missing HSTS header): manual_review — grep_present -> MANUAL_REVIEW
- **V-012** (Default credentials): pass — grep_absent -> PASS
- **V-009** (Lack of SSL pinning): fail — grep_absent -> FAIL
- **V-011** (MITM exposure): pass — exit_code_zero -> PASS
- **V-013** (Weak password policy): pass — exit_code_zero -> PASS
- **V-016** (Credential stuffing exposure): pass — grep_absent -> PASS
- **V-017** (Insecure password reset flow): manual_review — numeric_threshold -> MANUAL_REVIEW
- **V-018** (Session fixation): pass — exit_code_zero -> PASS
- **V-056** (Insecure session token design): manual_review — numeric_threshold -> MANUAL_REVIEW
## Key Observations
_Audit memory will accumulate here._

## Recommendations
_Pending first run._
