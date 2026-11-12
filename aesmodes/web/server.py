"""
server.py - a small Flask server for the AES learning app.

The browser page (static/) only draws things. Every number it shows comes from
this server, which calls the project's own AES and modes code (aesmodes/).

Endpoints (all JSON):
    GET  /api/sbox        S-box and inverse S-box
    POST /api/aes         one-block AES walkthrough       {key, block, blockFormat}
    POST /api/keys        key expansion details           {key}
    POST /api/mode        encrypt/decrypt in any mode     {mode, operation, key, data, dataFormat, counter}
    POST /api/bitflip     error-propagation experiment    {key, message, messageFormat, counter, byte, bit}
    POST /api/image       encrypt image pixels            {mode, key, counter, pixels (base64)}
"""

import base64
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from .. import __version__
from .. import explain as ex
from ..padding import PaddingError, pad

STATIC = Path(__file__).parent / "static"


def create_app() -> Flask:
    app = Flask(__name__, static_folder=str(STATIC), static_url_path="/static")

    def body() -> dict:
        return request.get_json(force=True, silent=True) or {}

    @app.errorhandler(ValueError)
    def bad_input(err):
        return jsonify(error=str(err)), 400

    @app.errorhandler(PaddingError)
    def bad_padding(err):
        return jsonify(error="The padding is invalid after decryption. This usually means a wrong "
                             "key, wrong mode, wrong counter, or a damaged ciphertext. "
                             f"({err})"), 400

    @app.get("/")
    def index():
        return send_from_directory(STATIC, "index.html")

    @app.get("/api/version")
    def version():
        return jsonify(version=__version__)

    @app.get("/api/sbox")
    def sbox():
        return jsonify(ex.sbox_tables())

    @app.post("/api/aes")
    def aes():
        b = body()
        key = ex.parse_key(b.get("key", ""))
        block = ex.parse_bytes(b.get("block", ""), b.get("blockFormat", "hex"), "Plaintext block")
        note = None
        if len(block) > 16:
            raise ValueError(f"AES encrypts exactly one 16-byte block; your input is {len(block)} "
                             "bytes. Use the Modes page for longer messages.")
        if len(block) < 16:
            note = (f"Your input is {len(block)} bytes, so it was padded to 16 bytes with the "
                    "project's padding (zeros + pad count).")
            block = pad(block)
        result = ex.aes_walkthrough(key, block)
        result["note"] = note
        return jsonify(result)

    @app.post("/api/keys")
    def keys():
        return jsonify(keyExpansion=ex.key_expansion_details(ex.parse_key(body().get("key", ""))))

    @app.post("/api/mode")
    def mode():
        b = body()
        key = ex.parse_key(b.get("key", ""))
        op = b.get("operation", "encrypt")
        fmt = "hex" if op == "decrypt" else b.get("dataFormat", "text")
        data = ex.parse_bytes(b.get("data", ""), fmt, "Ciphertext" if op == "decrypt" else "Message")
        counter = b.get("counter") or None
        return jsonify(ex.run_mode(b.get("mode", "ECB"), op, key, data, counter))

    @app.post("/api/bitflip")
    def bitflip():
        b = body()
        key = ex.parse_key(b.get("key", ""))
        msg = ex.parse_bytes(b.get("message", ""), b.get("messageFormat", "text"), "Message")
        counter = b.get("counter") or "1"
        return jsonify(ex.bitflip_experiment(key, msg, counter, int(b.get("byte", 0)),
                                             int(b.get("bit", 0))))

    @app.post("/api/image")
    def image():
        b = body()
        key = ex.parse_key(b.get("key", ""))
        pixels = base64.b64decode(b.get("pixels", ""))
        out = ex.encrypt_image(b.get("mode", "ECB"), key, pixels, b.get("counter") or "1")
        return jsonify(pixels=base64.b64encode(out).decode("ascii"))

    return app
