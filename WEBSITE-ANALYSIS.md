# Cortex website observations

Website analysis has a separate backend but shares the intake workflow: choose
Upload & collect → Collect from Network → Public website. Old `/website` links redirect
to that panel. Start the bridge with `make start` and the frontend with
`npm run dev` in `frontend` as before; no additional service or runtime is required.

## Scope

An explicit user action sends an unauthenticated GET to the supplied public URL,
following at most three redirects. Only HTTP(S) standard ports are supported. No
body is read or executed, no credentials or cookies are sent, no extra endpoints
are crawled and no vulnerability payloads are submitted. All DNS answers must be
public. Each connection is pinned to a validated IP while TLS verifies the original
hostname using the system trust store. Private-network configuration overrides do
not apply to website mode. HTTPS-to-HTTP redirects stop collection.

This is a limited HTTP/TLS observation, not an exhaustive vulnerability scanner.
It does not prove site-wide security, absence of vulnerabilities or compliance.
Header policies are conservative review items where presence/absence alone is not
enough. Cookie purposes, CSP effectiveness and browser meta policies require manual
review. Certificates are verified for the negotiated connection, not all supported
protocols/ciphers. TLS failures return an explicit error, never invented findings.

## API and data lifecycle

- `POST /api/website/analyze`: JSON `{ "url": "https://example.com/", "acknowledged": true }`.
  Returns `report` and `report_token`. No Java scoring or device session mutation.
- `POST /api/website/report/pdf`: JSON `{ "report_token": "..." }`.
  Exports exactly the signed observation; it does not fetch the target again.
- Tokens are signed with a random per-process key and expire after one hour or a
  bridge restart. For now, multiple worker processes require sticky routing.
- Reports exist only in the browser and signed token, not a report database.
  Both successful endpoints use `Cache-Control: no-store`. Download before leaving
  the page. URLs are not copied into navigation history or local storage.
- Query strings, cookie names/values and CSP nonces are omitted from reports.
  URL paths and other response-header values can still contain sensitive content.
  Do not submit private/signed URLs; this is not a general-purpose DLP filter.
- Two concurrent website observations per process; excess requests return 429.
  Connect/read timeouts and a 10-second response-header deadline bound network work.
  DNS resolution still depends on the host resolver. Use trusted local deployment;
  public exposure requires authentication, rate limiting and outbound network policy.
- Headers: 64 KiB aggregate cap; at most 3000 displayed characters per selected
  header and 4000 per finding. Cookie summaries cover at most 20 final-response
  cookies. HTTP challenges/error responses are explicitly marked for review.

## Input correction

Recognizable HTML documents are rejected before device ingestion in both the
bridge and Java ingestion boundary. This prevents the reported YouTube test from
being repeated through upload, paste or live collection. This is not a full grammar
validator for every vendor/export format. Existing sessions (including `aaa`) are
preserved; their previous HTML-derived findings are invalid evidence and should
not be used. Re-run the URL in Website mode rather than interpreting the old score.

## Verification

`python -m pytest bridge/tests/test_website.py -q` runs network-free checks for URL
validation, public IP policy, TLS hostname/IP pinning, redirects, redaction,
outcomes, HTML rejection, API isolation and PDF export. Install `pypdf` in the test
environment for the optional PDF text check. ReportLab is already a bridge dependency.
Tests use synthetic responses; they do not assert properties of real websites.
