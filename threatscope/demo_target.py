"""Intentionally vulnerable local-only target used by the ThreatScope scan lab."""

from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.get("/")
def index():
    return """<!doctype html><title>Demo Shop</title><h1>Local Demo Shop</h1>
    <a href='/search?q=blue+widget'>Search</a> · <a href='/account'>Account</a>"""


@app.get("/search")
def search():
    # Deliberately unsafe output in a network-isolated training target. Never copy.
    query = request.args.get("q", "")
    return render_template_string("<h1>Search results</h1><p>{{ query|safe }}</p>", query=query)


@app.get("/account")
def account():
    return "<h1>Demo account</h1><p>Fixture only; no real user data.</p>"


@app.get("/health")
def health():
    return "ok"


def main():
    app.run(host="0.0.0.0", port=5001, debug=False)


if __name__ == "__main__":
    main()
