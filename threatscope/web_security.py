"""HTTP hardening, request logging, error handling and rate limiting.

``install(app)`` wires everything into the Flask app:

* Security headers recommended by the OWASP Secure Headers Project. The UI is a
  single self-contained page, so the Content-Security-Policy only allows the
  app's own origin (inline code is needed because the page ships as one file).
* A request ID per request (accepted from ``X-Request-ID`` only when it is a
  short token, so a client cannot inject text into log lines).
* One structured access-log line per request: method, path, status, duration.
  Request bodies are never logged; they can contain passwords, files or logs.
* JSON error bodies for API routes, and a generic 500 that hides stack traces.

``rate_limited(n)`` caps how often one client may call an expensive endpoint
(external tools, deliberate slow hashing) per minute.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from functools import wraps

from flask import g, jsonify, request
from werkzeug.exceptions import HTTPException

CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
       "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
       "connect-src 'self'; font-src 'self' data:; object-src 'none'; "
       "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}
_RID = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_hits = defaultdict(deque)
_lock = threading.Lock()


def install(app, name: str) -> logging.Logger:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    log = logging.getLogger(name)

    @app.before_request
    def _start():
        g.t0 = time.perf_counter()
        supplied = request.headers.get("X-Request-ID", "")
        g.rid = supplied if _RID.match(supplied) else uuid.uuid4().hex[:12]

    @app.after_request
    def _finish(response):
        for key, value in HEADERS.items():
            response.headers.setdefault(key, value)
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        response.headers["X-Request-ID"] = g.get("rid", "")
        if request.path != "/health":
            ms = (time.perf_counter() - g.get("t0", time.perf_counter())) * 1000
            log.info("rid=%s method=%s path=%s status=%s ms=%.1f",
                     g.get("rid"), request.method, request.path, response.status_code, ms)
        return response

    @app.errorhandler(HTTPException)
    def _http_error(exc):
        if request.path.startswith("/api/"):
            return jsonify({"error": exc.description, "request_id": g.get("rid")}), exc.code
        return exc

    @app.errorhandler(Exception)
    def _crash(exc):
        log.exception("rid=%s unhandled error on %s", g.get("rid"), request.path)
        return jsonify({"error": "internal error", "request_id": g.get("rid")}), 500

    return log


def rate_limited(per_minute: int):
    """Allow at most ``per_minute`` calls per client address for this endpoint."""
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            key = (view.__name__, request.remote_addr or "?")
            now = time.monotonic()
            with _lock:
                window = _hits[key]
                while window and now - window[0] > 60:
                    window.popleft()
                if len(window) >= per_minute:
                    retry = int(60 - (now - window[0])) + 1
                    response = jsonify({"error": "rate limit reached; try again shortly",
                                        "retry_after_s": retry})
                    response.status_code = 429
                    response.headers["Retry-After"] = str(retry)
                    return response
                window.append(now)
            return view(*args, **kwargs)
        return wrapper
    return decorator


def reset_rate_limits() -> None:
    """Test helper: forget all recorded calls."""
    with _lock:
        _hits.clear()
