"""
server.py - a small Flask server for the AES learning app (local use).

    python -m aesmodes.web      ->  http://127.0.0.1:8455

The browser page (static/) only draws things. Every number it shows comes from
the request handlers in aesmodes/api.py, which call the project's own AES and
modes code. The web version on GitHub Pages runs exactly the same handlers
inside the browser with Pyodide, so both versions behave identically.
"""

from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from ..api import handle

STATIC = Path(__file__).parent / "static"


def create_app() -> Flask:
    app = Flask(__name__, static_folder=str(STATIC), static_url_path="/static")

    @app.get("/")
    def index():
        return send_from_directory(STATIC, "index.html")

    @app.route("/api/<path:route>", methods=["GET", "POST"])
    def api(route):
        body = request.get_json(force=True, silent=True) or {}
        status, data = handle(request.method, f"/api/{route}", body)
        return jsonify(data), status

    return app
