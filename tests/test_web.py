"""
Tests for the learning app's server (aesmodes/web) and explain.py.

They check that every number the app shows comes from the project's own AES and
modes code, and that bad input gives a clear error instead of a crash.
"""

import base64

import pytest

pytest.importorskip("flask")

from aesmodes import encrypt  # noqa: E402
from aesmodes.web import create_app  # noqa: E402

KEY = "2b7e151628aed2a6abf7158809cf4f3c"


@pytest.fixture()
def client():
    return create_app().test_client()


def test_index_page_served(client):
    r = client.get("/")
    assert r.status_code == 200 and b"AES" in r.data


def test_static_assets_served(client):
    for path in ["/static/css/style.css", "/static/js/aes.js", "/static/vendor/katex/katex.min.js"]:
        assert client.get(path).status_code == 200, path


def test_aes_walkthrough_matches_fips197(client):
    r = client.post("/api/aes", json={"key": KEY, "block": "3243f6a8885a308d313198a2e0370734"}).get_json()
    assert r["ciphertext"] == "3925841d02dc09fbdc118597196a0b32"
    assert len(r["steps"]) == 41
    # FIPS-197 Appendix B: round 1 after MixColumns, column 0 = 04 66 81 e5
    mix = next(s for s in r["steps"] if s["op"] == "MixColumns" and s["round"] == 1)
    assert mix["mix"][0]["out"] == ["04", "66", "81", "e5"]
    assert mix["mix"][0]["rows"][0]["terms"][0] == {"coef": 2, "byte": "d4", "product": "b3"}


def test_aes_short_text_is_padded_with_note(client):
    r = client.post("/api/aes", json={"key": KEY, "block": "hi", "blockFormat": "text"}).get_json()
    assert r["note"] and r["plaintext"].endswith("0e")          # 14 bytes of padding


def test_key_expansion(client):
    w = client.post("/api/keys", json={"key": KEY}).get_json()["keyExpansion"]
    assert len(w) == 44 and w[4]["word"] == "a0fafe17" and w[43]["word"] == "b6630ca6"
    assert w[4]["kind"] == "g" and w[4]["rot"] == "cf4f3c09" and w[4]["sub"] == "8a84eb01"


@pytest.mark.parametrize("mode", ["ECB", "CBC", "CFB", "OFB", "CTR"])
def test_mode_round_trip_and_matches_library(client, mode):
    msg = "Hello, AES modes! This message is longer than one block."
    enc = client.post("/api/mode", json={"mode": mode, "operation": "encrypt", "key": KEY,
                                         "data": msg, "counter": "1"}).get_json()
    assert enc["output"] == encrypt(mode, bytes.fromhex(KEY), msg.encode(), counter="1").hex()
    assert enc["padCount"] == 8 and len(enc["steps"]) == 4
    dec = client.post("/api/mode", json={"mode": mode, "operation": "decrypt", "key": KEY,
                                         "data": enc["output"], "counter": "1"}).get_json()
    assert dec["outputText"] == msg


def test_wrong_key_gives_padding_message(client):
    enc = client.post("/api/mode", json={"mode": "CBC", "operation": "encrypt", "key": KEY, "data": "hi"}).get_json()
    r = client.post("/api/mode", json={"mode": "CBC", "operation": "decrypt", "key": "00" * 16, "data": enc["output"]})
    assert r.status_code == 400 and "wrong key" in r.get_json()["error"]


@pytest.mark.parametrize("payload", [
    {"key": "xyz", "block": "00" * 16},
    {"key": KEY, "block": "00" * 17},
    {"key": KEY[:-2], "block": "00" * 16},
])
def test_bad_aes_input_is_400(client, payload):
    r = client.post("/api/aes", json=payload)
    assert r.status_code == 400 and r.get_json()["error"]


def test_bitflip_experiment(client):
    r = client.post("/api/bitflip", json={"key": KEY, "message": "A" * 64, "byte": 3, "bit": 2}).get_json()
    bits = {m["mode"]: [b["bits"] for b in m["blocks"]] for m in r["modes"]}
    assert bits["OFB"][:2] == [1, 0] and bits["CTR"][:2] == [1, 0]
    assert bits["CBC"][1] == 1 and bits["CFB"][0] == 1


def test_image_encryption_keeps_length(client):
    pixels = bytes(range(256)) * 4
    r = client.post("/api/image", json={"mode": "ECB", "key": KEY,
                                        "pixels": base64.b64encode(pixels).decode()}).get_json()
    assert len(base64.b64decode(r["pixels"])) == len(pixels)
