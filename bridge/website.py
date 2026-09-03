"""Bounded, unauthenticated website observations; never device compliance scores."""
from __future__ import annotations

import http.client
import ipaddress
import re
import secrets
import socket
import ssl
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit, urlunsplit, quote

from flask import Blueprint, jsonify, request, Response
from itsdangerous import URLSafeTimedSerializer, BadData

bp = Blueprint("website", __name__)
# In-memory, per-process signing key: no report database, no reliance on the dev Flask secret.
_signer = URLSafeTimedSerializer(secrets.token_bytes(32), salt="cortex-website-v1")
_slots = threading.BoundedSemaphore(2)
HEADER_NAMES = (
    "content-type", "strict-transport-security", "content-security-policy",
    "content-security-policy-report-only", "x-frame-options",
    "x-content-type-options", "referrer-policy",
)
LIMITATIONS = [
    "One unauthenticated GET per URL, at most three redirects. Response bodies are not read or executed; no crawling, login, port scanning, payload injection or exploitation.",
    "Observations apply only to these responses from this network at the recorded time. CDN, region, bot checks, consent pages and authentication can change the result.",
    "Header presence is not proof of effective protection. Missing headers are review items, not confirmed exploitable vulnerabilities. HTML meta policies and browser defaults are not evaluated.",
    "No device configuration, internal network, database, authorization, CVE, malware, blockchain integrity or compliance certification is assessed. No overall security or compliance score is calculated.",
    "URL query strings and cookie values are omitted from the report. Paths may still contain sensitive identifiers; avoid submitting private or signed URLs. Reports are not stored by this service.",
]


class WebsiteError(ValueError):
    """Safe, actionable public error."""


def validate_url(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise WebsiteError("Enter an HTTP or HTTPS URL of at most 2048 characters.")
    value = value.strip()
    if any(ord(c) < 33 or ord(c) == 127 for c in value) or "\\" in value:
        raise WebsiteError("URL contains unsupported whitespace or characters.")
    try:
        p = urlsplit(value)
        if p.scheme not in ("http", "https") or not p.hostname or p.username is not None or p.password is not None:
            raise ValueError()
        port = p.port or (443 if p.scheme == "https" else 80)
        if port != (443 if p.scheme == "https" else 80):
            raise ValueError()
        host = p.hostname.encode("idna").decode("ascii")
    except (ValueError, UnicodeError):
        raise WebsiteError("Use HTTP port 80 or HTTPS port 443, with a hostname and no embedded credentials.") from None
    authority = f"[{host}]" if ":" in host else host
    return urlunsplit((p.scheme, authority, quote(p.path or "/", safe="/%:@!$&'()*+,;=-._~"), quote(p.query, safe="%/:?@!$&'()*+,;=-._~"), ""))


def display_url(value):
    p = urlsplit(value)
    return urlunsplit((p.scheme, p.netloc, p.path, "[redacted]" if p.query else "", ""))


def public_address(host, port):
    # Validate all answers, then connect directly to one validated IP. No second DNS
    # lookup during connection; redirects repeat this check. Private override is ignored.
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(a[4][0] for a in answers))
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise WebsiteError("Website mode only permits public internet addresses; private and local targets are blocked.")
    return addresses[0]


def observe(url):
    p = urlsplit(url)
    port = 443 if p.scheme == "https" else 80
    address = public_address(p.hostname, port)
    conn = http.client.HTTPConnection(p.hostname, port, timeout=8)
    sock = None
    deadline = None
    try:
        sock = socket.create_connection((address, port), timeout=8)
        tls = None
        if p.scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=p.hostname)
            cert = sock.getpeercert()
            tls = {"version": sock.version(), "cipher": sock.cipher()[0], "certificate_expires": cert.get("notAfter", "Not available"), "verification": "Hostname and certificate chain verified against the system trust store"}
        conn.sock = sock
        # Bound slow/trickling headers, not only idle socket reads.
        def stop_socket():
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        deadline = threading.Timer(10, stop_socket)
        deadline.daemon = True
        deadline.start()
        conn.request("GET", urlunsplit(("", "", p.path or "/", p.query, "")), headers={"User-Agent": "Cortex-Website/1.0", "Accept": "text/html, */*;q=0.5", "Connection": "close"})
        response = conn.getresponse()
        pairs = response.getheaders()
        if sum(len(k) + len(v) for k, v in pairs) > 65536:
            raise WebsiteError("Response headers exceed the assessment limit.")
        headers = {name: ", ".join(v for k, v in pairs if k.lower() == name) for name in HEADER_NAMES}
        cookies = [v for k, v in pairs if k.lower() == "set-cookie"]
        return {"url": display_url(url), "status": response.status, "headers": headers, "tls": tls, "cookies": cookies, "location": response.getheader("Location"), "peer_ip": address}
    finally:
        if deadline is not None:
            deadline.cancel()
        conn.close()
        if sock is not None:
            sock.close()


def findings_for(hops):
    last = hops[-1]
    h = last["headers"]
    findings = []
    def add(code, title, verdict, evidence, why, fix, verify, reference):
        findings.append(dict(id=code, title=title, verdict=verdict, evidence=evidence, explanation=why, remediation=fix, verification=verify, reference=reference))
    secure = all(hop["tls"] for hop in hops)
    add("WEB-01", "Transport on the observed route", "pass" if secure else "fail",
        "All observed hops used verified HTTPS." if secure else "At least one observed request used unencrypted HTTP.",
        "HTTP traffic can be observed or modified in transit. A later redirect does not protect the first HTTP request.",
        "Use an HTTPS entry URL; have the site owner enforce HTTPS. This check does not probe alternate HTTP URLs.",
        "Repeat the assessment with the public HTTPS URL and inspect every redirect.", "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security")
    tls_evidence = "; ".join(f"{k.replace('_', ' ').title()}: {v}" for k, v in (last["tls"] or {}).items())
    add("WEB-02", "TLS connection and certificate", "pass" if last["tls"] else "not_tested",
        tls_evidence or "The final response used HTTP; no TLS certificate was received.",
        "A successful verified handshake establishes trust for this connection, not support for every protocol or cipher.",
        "Maintain hostname-matching certificates and renew before expiry; perform a separate authorized TLS configuration assessment for full coverage.",
        "Review certificate renewal monitoring and test with a trusted TLS client.", "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security")
    hsts = h.get("strict-transport-security", "")
    age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", hsts, re.I)
    good_hsts = bool(last["tls"] and age and int(age[1]) > 0 and "," not in hsts)
    try:
        ipaddress.ip_address(urlsplit(last["url"]).hostname)
        good_hsts = False  # Browsers do not store HSTS policies for IP literals.
    except ValueError:
        pass
    add("WEB-03", "HTTP Strict Transport Security", "pass" if good_hsts else "manual_review", hsts or "Header not observed.",
        "An effective HSTS header tells browsers to use HTTPS on later visits. This check only recognizes a positive max-age on HTTPS; preload and existing browser policy are not tested.",
        "Review HTTPS readiness before enabling HSTS. Choose max-age and subdomain scope deliberately; do not enable preload without operational review.",
        "Inspect the HTTPS response for a single Strict-Transport-Security policy with positive max-age.", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security")
    add("WEB-04", "Content Security Policy", "manual_review", h.get("content-security-policy") or "No enforcing CSP response header observed.",
        "CSP needs application-specific review. Presence alone cannot prove protection against script injection; report-only policy is not enforcement.",
        "Inventory required script sources, test a restrictive policy in report-only mode, then enforce after reviewing breakage and reports.",
        "Review browser console violations and application behavior; inspect nonce/hash generation and third-party sources.", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy")
    add("WEB-05", "Framing policy", "manual_review", "X-Frame-Options: " + (h.get("x-frame-options") or "not observed") + "; CSP frame-ancestors requires policy review.",
        "Embedding rules depend on intended integrations. This assessment does not try to frame the page or parse all CSP policies.",
        "Have the owner review CSP frame-ancestors and any legacy X-Frame-Options against approved embedding origins.",
        "Test approved and unapproved framing scenarios in a browser.", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy")
    nosniff = h.get("x-content-type-options", "").lower().strip() == "nosniff"
    add("WEB-06", "MIME sniffing protection", "pass" if nosniff else "manual_review", h.get("x-content-type-options") or "Header not observed.",
        "The nosniff response directive limits MIME-type guessing. Other endpoints and resource types have not been fetched.",
        "Serve correct Content-Type values and configure X-Content-Type-Options: nosniff where appropriate.",
        "Inspect response headers for HTML, script and style resources with their owner; verify normal loading.", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options")
    add("WEB-07", "Referrer policy", "manual_review", h.get("referrer-policy") or "No response header observed; browser defaults or HTML policies may apply.",
        "Referrer rules influence information sent during navigation. Missing header alone is not a confirmed leak.",
        "Choose a policy compatible with application needs and avoid secrets in URLs.",
        "Inspect outgoing Referer behavior in a browser on same-origin and cross-origin navigation.", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy")
    cookie_lines = []
    for i, cookie in enumerate(last["cookies"][:20], 1):
        attrs = [p.strip().lower() for p in cookie.split(";")[1:]]
        same = next((p for p in attrs if p.startswith("samesite=")), "samesite not observed")
        cookie_lines.append(f"Cookie {i}: Secure={'secure' in attrs}; HttpOnly={'httponly' in attrs}; {same}. Value/name omitted.")
    add("WEB-08", "Response cookie attributes", "manual_review" if last["cookies"] else "not_tested",
        " ".join(cookie_lines) or "No Set-Cookie header observed on the final response.",
        "Cookie purpose is unknown without an authenticated application review. JavaScript-readable cookies are not automatically defects. Login and later responses are not assessed; at most 20 cookies are summarized.",
        "Review sensitive session cookies for Secure, HttpOnly and suitable SameSite settings; preserve intentional client-readable behavior.",
        "Inspect authentication cookies and cross-site workflows in an authorized browser session.", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie")
    add("WEB-09", "Response representativeness", "manual_review", f"Final HTTP status: {last['status']}; Content-Type: {h.get('content-type') or 'not observed'}.",
        "A successful response may still be a bot challenge, consent page or regional variant. Headers on errors are not evidence of the normal application response.",
        "Confirm that the observed public endpoint represents the intended page with its owner.",
        "Compare with an authorized browser session and record any authentication, geography or CDN differences.", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status")
    add("WEB-10", "Internal controls and exploitability", "not_tested", "No internal evidence or active vulnerability testing collected.",
        "A public URL cannot establish device configuration, access-control correctness, full compliance or the absence of vulnerabilities.",
        "Use the device auditor for actual device exports. Arrange a separately scoped, authorized application assessment for internal controls.",
        "Obtain appropriate configuration, design and test evidence before making assurance claims.", "")
    return findings


def assess(url):
    current = validate_url(url)
    start = time.monotonic()
    hops = []
    for i in range(4):
        if time.monotonic() - start > 35:
            raise WebsiteError("Assessment exceeded its time budget. Try again later.")
        hop = observe(current)
        hops.append(hop)
        if hop["status"] not in (301, 302, 303, 307, 308):
            break
        if i == 3 or not hop["location"]:
            raise WebsiteError("Redirect chain could not be completed within three redirects.")
        next_url = validate_url(urljoin(current, hop["location"]))
        if current.startswith("https:") and next_url.startswith("http:"):
            raise WebsiteError("The site redirected HTTPS to HTTP. Collection stopped to avoid a transport downgrade.")
        current = next_url
    findings = findings_for(hops)
    for hop in hops:
        hop.pop("cookies", None)
        hop.pop("location", None)
        hop["headers"] = {k: re.sub(r"'nonce-[^']*'", "'nonce-[redacted]'", v)[:3000] for k, v in hop["headers"].items() if v}
    for finding in findings:
        finding["evidence"] = re.sub(r"'nonce-[^']*'", "'nonce-[redacted]'", finding["evidence"])[:4000]
    return dict(kind="website_observation", version=1, id=secrets.token_hex(8), generated_at=datetime.now(timezone.utc).isoformat(), target=display_url(validate_url(url)), final_url=hops[-1]["url"], hops=hops, findings=findings, counts=dict(Counter(f["verdict"] for f in findings)), limitations=LIMITATIONS)


@bp.post("/api/website/analyze")
def analyze_website():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or data.get("acknowledged") is not True:
        return jsonify(error="Confirm that you may assess this public URL and understand the limited scope."), 400
    try:
        url = validate_url(data.get("url"))
    except WebsiteError as exc:
        return jsonify(error=str(exc)), 400
    if not _slots.acquire(blocking=False):
        return jsonify(error="Website assessments are busy. Please retry shortly."), 429
    try:
        report = assess(url)
        return jsonify(report=report, report_token=_signer.dumps(report)), 200, {"Cache-Control": "no-store"}
    except WebsiteError as exc:
        return jsonify(error=str(exc)), 400
    except ssl.SSLCertVerificationError:
        return jsonify(error="TLS certificate verification failed. No HTTP findings were produced; do not bypass certificate validation."), 502
    except (OSError, http.client.HTTPException, UnicodeError, ValueError):
        return jsonify(error="Unable to observe this website. Check the URL, public DNS and reachability, then retry. No security verdict was inferred."), 502
    finally:
        _slots.release()


@bp.post("/api/website/report/pdf")
def website_pdf():
    data = request.get_json(silent=True)
    token = data.get("report_token") if isinstance(data, dict) else None
    if not isinstance(token, str) or len(token) > 100000:
        return jsonify(error="A completed website assessment is required."), 400
    try:
        report = _signer.loads(token, max_age=3600)
    except BadData:
        return jsonify(error="Report expired or the bridge restarted. Run the assessment again."), 400
    try:
        from bridge.website_report import build_pdf
    except ImportError:
        from website_report import build_pdf
    return Response(build_pdf(report), mimetype="application/pdf", headers={"Content-Disposition": f'attachment; filename=cortex_website_{report["id"]}.pdf', "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
