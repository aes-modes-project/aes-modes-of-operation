"""
api.py - the request handlers of the learning app, in plain Python.

The same handlers are used in two places:

  * the Flask server (aesmodes/web/server.py), when you run
        python -m aesmodes.web
  * the web version on GitHub Pages, where the browser runs this Python code
    itself with Pyodide (Python compiled to WebAssembly), so no server is needed.

Every handler takes the request body as a dict and returns (status, data).
Only the Python standard library is used here, so it runs in both places.

Routes:
    GET  /api/version     package version
    GET  /api/sbox        S-box and inverse S-box
    POST /api/aes         one-block AES walkthrough       {key, block, blockFormat}
    POST /api/keys        key expansion details           {key}
    POST /api/mode        encrypt/decrypt in any mode     {mode, operation, key, data, dataFormat, counter}
    POST /api/bitflip     error-propagation experiment    {key, message, messageFormat, counter, byte, bit}
    POST /api/image       encrypt image pixels            {mode, key, counter, pixels (base64)}
"""

import base64
from typing import Callable, Dict, Tuple

from . import __version__
from . import explain as ex
from .padding import PaddingError, pad

Response = Tuple[int, dict]


def _version(_: dict) -> dict:
    return {"version": __version__}


def _sbox(_: dict) -> dict:
    return ex.sbox_tables()


def _aes(b: dict) -> dict:
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
    return result


def _keys(b: dict) -> dict:
    return {"keyExpansion": ex.key_expansion_details(ex.parse_key(b.get("key", "")))}


def _mode(b: dict) -> dict:
    key = ex.parse_key(b.get("key", ""))
    op = b.get("operation", "encrypt")
    fmt = "hex" if op == "decrypt" else b.get("dataFormat", "text")
    data = ex.parse_bytes(b.get("data", ""), fmt, "Ciphertext" if op == "decrypt" else "Message")
    counter = b.get("counter") or None
    return ex.run_mode(b.get("mode", "ECB"), op, key, data, counter)


def _bitflip(b: dict) -> dict:
    key = ex.parse_key(b.get("key", ""))
    msg = ex.parse_bytes(b.get("message", ""), b.get("messageFormat", "text"), "Message")
    counter = b.get("counter") or "1"
    return ex.bitflip_experiment(key, msg, counter, int(b.get("byte", 0)), int(b.get("bit", 0)))


def _image(b: dict) -> dict:
    key = ex.parse_key(b.get("key", ""))
    pixels = base64.b64decode(b.get("pixels", ""))
    out = ex.encrypt_image(b.get("mode", "ECB"), key, pixels, b.get("counter") or "1")
    return {"pixels": base64.b64encode(out).decode("ascii")}


ROUTES: Dict[Tuple[str, str], Callable[[dict], dict]] = {
    ("GET", "/api/version"): _version,
    ("GET", "/api/sbox"): _sbox,
    ("POST", "/api/aes"): _aes,
    ("POST", "/api/keys"): _keys,
    ("POST", "/api/mode"): _mode,
    ("POST", "/api/bitflip"): _bitflip,
    ("POST", "/api/image"): _image,
}

PADDING_MESSAGE = ("The padding is invalid after decryption. This usually means a wrong key, wrong "
                   "mode, wrong counter, or a damaged ciphertext. ({})")


def handle(method: str, path: str, body: dict = None) -> Response:
    """Run one request. Returns (HTTP status, JSON-ready dict)."""
    fn = ROUTES.get((method.upper(), "/" + path.lstrip("/")))
    if fn is None:
        return 404, {"error": f"Unknown request {method} {path}"}
    try:
        return 200, fn(body or {})
    except PaddingError as err:
        return 400, {"error": PADDING_MESSAGE.format(err)}
    except (ValueError, TypeError) as err:
        return 400, {"error": str(err)}
