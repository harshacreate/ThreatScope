"""Security behaviour of the HTTP layer (headers, request IDs, errors, limits)."""
from threatscope.app import app
from threatscope.web_security import reset_rate_limits


def client():
    reset_rate_limits()
    return app.test_client()


def test_security_headers_on_page_and_api():
    c = client()
    for path in ("/", "/health"):
        h = c.get(path).headers
        assert "default-src 'self'" in h["Content-Security-Policy"]
        assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
        assert h["X-Content-Type-Options"] == "nosniff"
        assert h["X-Frame-Options"] == "DENY"
        assert h["Referrer-Policy"] == "no-referrer"


def test_api_responses_are_not_cached():
    assert client().get("/api/does-not-exist").headers["Cache-Control"] == "no-store"


def test_request_id_is_echoed_only_when_safe():
    c = client()
    assert c.get("/health", headers={"X-Request-ID": "abc-123"}).headers["X-Request-ID"] == "abc-123"
    forged = "evil path=/admin status=200"
    injected = c.get("/health", headers={"X-Request-ID": forged}).headers["X-Request-ID"]
    assert injected != forged and len(injected) == 12


def test_unknown_api_route_returns_json_error():
    r = client().get("/api/does-not-exist")
    assert r.status_code == 404 and "error" in r.get_json()


def test_expensive_endpoint_is_rate_limited():
    c = client()
    call = c.post if "POST" == "POST" else c.get
    codes = [call("/api/nmap-demo").status_code for _ in range(4 + 1)]
    assert all(code != 429 for code in codes[:-1])
    assert codes[-1] == 429
    reset_rate_limits()


def test_optional_api_token(monkeypatch):
    c = client()
    assert c.get("/api/dashboard").status_code == 200          # off by default
    monkeypatch.setenv("THREATSCOPE_API_TOKEN", "s3cret-token-value")
    denied = c.get("/api/dashboard")
    assert denied.status_code == 401 and "Bearer" in denied.headers["WWW-Authenticate"]
    assert denied.headers["X-Frame-Options"] == "DENY"          # hardening still applied
    assert c.get("/api/dashboard", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.get("/api/dashboard", headers={"Authorization": "Bearer s3cret-token-value"}).status_code == 200
    assert c.get("/health").status_code == 200                  # health check stays open for Docker
    assert c.get("/").status_code == 200                        # page loads, then prompts for the token
