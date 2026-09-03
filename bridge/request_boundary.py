"""Browser boundary for the single-user, loopback-only bridge (not authentication)."""

from urllib.parse import urlsplit
import ipaddress
from flask import jsonify, request

LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}


def install_request_boundary(app):
    @app.before_request
    def protect_local_api():
        if not request.path.startswith("/api/"):
            return None
        try:
            local_peer = ipaddress.ip_address(request.remote_addr or "").is_loopback
        except ValueError:
            local_peer = False
        if not local_peer:
            return jsonify(error="Cortex is a single-user local tool; remote API access is disabled."), 403
        # Do not trust X-Forwarded-Host or arbitrary DNS names resolving to loopback.
        try:
            host = urlsplit("http://" + request.host).hostname
        except ValueError:
            host = None
        if host not in LOOPBACK_NAMES:
            return jsonify(error="The Cortex API is available through a loopback hostname only."), 403
        origin = request.headers.get("Origin")
        if origin:
            try:
                parsed = urlsplit(origin)
                allowed = (parsed.scheme in {"http", "https"}
                           and parsed.hostname in LOOPBACK_NAMES
                           and parsed.port in {None, 5000, 5001, 5173, 5174, 4173}
                           and not parsed.username and not parsed.password
                           and not parsed.path and not parsed.query and not parsed.fragment)
            except ValueError:
                allowed = False
            if not allowed:
                return jsonify(error="Browser origin is not permitted to access the local Cortex API."), 403
        elif request.headers.get("Sec-Fetch-Site") == "cross-site":
            return jsonify(error="Cross-site browser requests are not permitted."), 403
        return None

    @app.after_request
    def private_response(response):
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Referrer-Policy"] = "no-referrer"
        return response
