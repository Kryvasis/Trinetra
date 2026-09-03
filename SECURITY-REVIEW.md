# Cortex security review — 2026-09-04

## Assessment

Cortex is a single-user local configuration-assessment prototype, not a production
multi-tenant scanner, penetration test, or compliance certification service. This
review covered intake, collection boundaries, scoring/report semantics, and regression
checks. It is not an exhaustive audit of every vendor rule or dependency.

## Changes

- All inputs now live under Upload & collect. Collect from Network offers SSH device,
  Configuration URL, and Public website. `/website` redirects to the website panel.
  Website analysis never passes HTML into the Java device-scoring pipeline.
- The local API rejects non-loopback peers, untrusted Host values, hostile Origin
  values, and cross-site browser requests without an accepted origin. API responses
  are no-store and nosniff. These are browser/DNS-rebinding defenses, not authentication.
  Trusted browser origins are HTTP(S) localhost, 127.0.0.1, or ::1 on default ports
  or ports 5000, 5001, 5173, 5174, 4173. Custom ports require an explicit reviewed change.
- Configuration downloads pin the connection to a validated IP and preserve the
  original TLS hostname verification. Environment proxy settings stay disabled;
  every redirect is revalidated, HTTPS downgrades blocked, cross-host credentials stripped.
- Collection tokens require HTTPS and Authorization or X-prefixed header names;
  control characters are rejected. SSH nonzero exits reject even partial output.
  Configuration size limits measure UTF-8 bytes, not characters.
- `tests_failed` now means explicit `fail` only. New fields: `tests_manual_review`,
  `tests_errors`, `tests_not_tested`, `tests_not_passed`. `compliance_percentage`
  keeps its API name and arithmetic for compatibility but means mapped-check pass
  rate. All unresolved outcomes remain in its denominator. Consumers must no longer
  assume passed + failed = total. Zero mapped checks means no assessment, not failure.
- Uploaded configuration text cannot prove command exit codes or runtime numeric
  measurements. Those rules now require manual review. Text-match rules remain
  heuristic and require complete configuration and applicability review.
- Explicit report exports rebuild scores and narratives to avoid stale artifacts.
  PDF tables preserve missing metadata columns, collect evidence across selected
  frameworks, include outcome summaries, and disclose the 60-row PDF display limit.
  Existing reports are not bulk-migrated. Re-exporting regenerates canonical report
  files; archive a historical report first if it must be preserved. When an LLM is
  configured, regeneration can invoke that existing integration again.
- Intake source changes clear collection credentials. Pending collection locks source
  switches; unmount aborts browser requests. Session creation has a timeout. Bulk
  filename collisions are rejected and timeout stops remaining submissions.
  Client cancellation does not prove cancellation of a server-side operation; inspect
  session state before retrying an uncertain upload.

## Important remaining limitations

- Do not expose the bridge or Vite development server publicly, or use a reverse
  proxy to bypass the local boundary. There is no user authentication, RBAC, tenant
  isolation, or production deployment model. Other local processes remain trusted.
- Stored configurations and raw evidence can contain device secrets. Collection
  credentials are transient, but that does not make uploaded configuration content
  secret-free. Use sanitized fixtures and restricted filesystem permissions. No
  encryption-at-rest, retention policy, or comprehensive redaction was added here.
- Private configuration URLs remain an explicit operator opt-in via
  `TRINETRA_LIVE_FETCH_ALLOW_PRIVATE_URLS`; this expands outbound reach and must only
  be used in a trusted environment. Website mode never honors that override.
- HTTP configuration collection has per-operation read/connect timeouts and a body
  limit, not a complete wall-clock budget against slow trickle responses. DNS also
  depends on the OS resolver. Public deployment requires stronger resource isolation,
  rate limiting, bounded jobs and egress policy.
- Benchmark mappings and config-text matching are not proof of control effectiveness.
  All vendor/OS-specific parsing needs a validated rule corpus before production use.
  Historical ingestion verdicts are not rewritten; re-ingest sanitized evidence to
  apply changed runtime-evidence rules. A report export only rescoring old evidence
  cannot correct an old incorrect underlying verdict.
- Hash-chain integrity is tamper evidence, not an independently trusted attestation.
  Someone controlling both files and execution can alter the trust base.
- LLM narrative number validation is not factual validation. Review recommendations
  and applicability; do not apply remediation commands automatically.
- Concurrent mutation and report export are not a transactionally frozen snapshot.
  Avoid adding evidence while exporting; a future job/snapshot model is recommended.

## Verification

Tests must run in a disposable copy: several legacy bridge tests modify the global
brain-state file even when they clean up their session directories. Never point a
test copy's `TRINETRA_ROOT` or `TRINETRA_BIN` back at the working repository.

This review uses an isolated repository and synthetic fixtures. New regressions
cover browser boundaries, unsafe credentials, DNS rebinding, TLS hostname pinning,
SSH partial failure, upload limits and distinct score outcomes. No production target
was scanned and no session data was migrated.

Run `.venv/bin/python tests/run_isolated.py` from the WSL repository to compile/run
all Java suites and bridge tests in a disposable copy. It removes root overrides,
skips environment files/runtime evidence, and rejects symlinks before testing.
Verified: 11 Java suites; 96 Python tests passed, one optional PDF-text test skipped
because pypdf is not installed in the project venv; frontend ESLint and Vite build;
strict UI audit (zero findings); desktop/mobile intake, validation/private-target
rejection, cleared credentials, synthetic ingestion and browser console check.
The generated synthetic PDF was rendered to check column alignment and outcomes.
