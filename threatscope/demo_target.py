"""A local sample app with known security bugs. The scan lab uses it for practice."""

from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.get("/")
def index():
    return """<!doctype html><title>Demo Shop</title><h1>Local Demo Shop</h1>
    <a href='/search?q=blue+widget'>Search</a>, <a href='/account'>Account</a>"""


@app.get("/search")
def search():
    # This unsafe output is only for the local training app. Do not copy it.
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
