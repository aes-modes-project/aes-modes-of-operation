"""
Tests for the file/message encryptor: fastaes.py (lookup-table AES) and filecrypt.py.

The encryptor must give exactly the same ciphertext as the teaching code
(aes_core.py, modes.py), and it must detect wrong keys and modified files.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from aesmodes import AES, encrypt
from aesmodes.fastaes import FastAES
from aesmodes.filecrypt import (
    MAGIC,
    IntegrityError,
    ModeStream,
    decrypt_container,
    decrypt_text,
    encrypt_container,
    encrypt_text,
    read_header,
    stream_apply,
)
from aesmodes.modes import MODE_NAMES
from aesmodes.padding import pad

FAST = {"iterations": 1000}          # keep PBKDF2 quick in tests


# ------------------------------------------------------------------ FastAES
@pytest.mark.parametrize("n, expected", [
    (16, "69c4e0d86a7b0430d8cdb78070b4c55a"),        # FIPS-197 C.1
    (24, "dda97ca4864cdfe06eaf70a0ec0d7191"),        # FIPS-197 C.2
    (32, "8ea2b7ca516745bfeafc49904b496089"),        # FIPS-197 C.3
])
def test_fastaes_fips197(n, expected):
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    f = FastAES(bytes(range(n)))
    assert f.encrypt_block(pt).hex() == expected
    assert f.decrypt_block(bytes.fromhex(expected)) == pt


@pytest.mark.parametrize("n", [16, 24, 32])
def test_fastaes_equals_teaching_aes(n):
    for _ in range(300):
        key, block = os.urandom(n), os.urandom(16)
        a, f = AES(key), FastAES(key)
        assert f.encrypt_block(block) == a.encrypt_block(block)
        assert f.decrypt_block(block) == a.decrypt_block(block)


def test_fastaes_rejects_bad_key():
    with pytest.raises(ValueError):
        FastAES(bytes(20))


# ------------------------------------------------------------------ ModeStream
@pytest.mark.parametrize("mode", MODE_NAMES)
@pytest.mark.parametrize("n", [16, 24, 32])
def test_stream_equals_modes_py(mode, n):
    key, msg = os.urandom(n), os.urandom(123)
    expected = encrypt(mode, key, msg, counter="0a").output
    assert ModeStream(mode, key, counter="0a").process(pad(msg)) == expected
    back = ModeStream(mode, key, decrypt=True, counter="0a").process(expected)
    assert back == pad(msg)


@pytest.mark.parametrize("mode", MODE_NAMES)
def test_stream_in_chunks_equals_one_go(mode):
    key, data = os.urandom(32), os.urandom(16 * 100)
    one = ModeStream(mode, key, counter=3).process(data)
    seen = []
    chunked = stream_apply(ModeStream(mode, key, counter=3), data,
                           progress=lambda d, t: seen.append(d), chunk_blocks=7)
    assert chunked == one and seen[-1] == len(data)


def test_stream_nist_cbc_vector():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    p = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    c = ModeStream("CBC", key, iv=bytes(range(16))).process(p)
    assert c.hex() == "7649abac8119b246cee98e9b12e9197d"           # SP 800-38A F.2.1


def test_stream_needs_whole_blocks():
    with pytest.raises(ValueError):
        ModeStream("ECB", bytes(16)).process(b"short")


# ------------------------------------------------------------------ containers
@pytest.mark.parametrize("mode", MODE_NAMES)
@pytest.mark.parametrize("bits", [128, 192, 256])
def test_password_round_trip(mode, bits):
    data = os.urandom(300)
    blob = encrypt_container(data, mode=mode, password="correct horse", key_bits=bits,
                             counter="ff", name="notes.txt", **FAST)
    plain, info = decrypt_container(blob, password="correct horse")
    assert plain == data
    assert info["mode"] == mode and info["keyBits"] == bits and info["name"] == "notes.txt"


@pytest.mark.parametrize("hexkey", ["00" * 16, "11" * 24, "22" * 32])
def test_hex_key_round_trip(hexkey):
    blob = encrypt_container(b"secret", mode="CFB", hex_key=hexkey)
    assert decrypt_container(blob, hex_key=hexkey)[0] == b"secret"
    assert read_header(blob)["keyBits"] == len(hexkey) * 4


def test_container_body_is_the_mode_ciphertext():
    """With a hex key and zero IV, the body is exactly the modes.py ciphertext."""
    key = os.urandom(16)
    blob = encrypt_container(b"Hello, AES modes!", mode="CBC", hex_key=key.hex())
    info = read_header(blob)
    body = blob[info["bodyStart"]:-32]
    assert body == encrypt("CBC", key, b"Hello, AES modes!").output


def test_ctr_counter_is_stored_and_used():
    blob = encrypt_container(b"x" * 40, mode="CTR", hex_key="00" * 16, counter="f0f1")
    assert int.from_bytes(read_header(blob)["iv"], "big") == 0xF0F1
    assert decrypt_container(blob, hex_key="00" * 16)[0] == b"x" * 40


def test_wrong_password_is_detected():
    blob = encrypt_container(b"data", password="right", **FAST)
    with pytest.raises(IntegrityError):
        decrypt_container(blob, password="wrong")


def test_wrong_key_size_is_detected():
    blob = encrypt_container(b"data", hex_key="00" * 32)
    with pytest.raises(IntegrityError):
        decrypt_container(blob, hex_key="00" * 16)


@pytest.mark.parametrize("pos", [5, 30, 60, -40, -1])
def test_any_change_is_detected(pos):
    blob = bytearray(encrypt_container(b"important file contents" * 3, password="pw", **FAST))
    blob[pos] ^= 0x01
    with pytest.raises((IntegrityError, ValueError)):
        decrypt_container(bytes(blob), password="pw")


def test_zero_iv_is_deterministic_random_iv_is_not():
    a = encrypt_container(b"same", mode="CBC", hex_key="00" * 16)
    b = encrypt_container(b"same", mode="CBC", hex_key="00" * 16)
    assert a == b                                            # project spec: zero IV
    c = encrypt_container(b"same", mode="CBC", hex_key="00" * 16, random_iv=True)
    d = encrypt_container(b"same", mode="CBC", hex_key="00" * 16, random_iv=True)
    assert c != d and read_header(c)["iv"] != bytes(16)
    assert decrypt_container(c, hex_key="00" * 16)[0] == b"same"


def test_password_salt_is_random():
    a = encrypt_container(b"same", password="pw", **FAST)
    b = encrypt_container(b"same", password="pw", **FAST)
    assert a != b and read_header(a)["salt"] != read_header(b)["salt"]


def test_empty_file():
    blob = encrypt_container(b"", password="pw", **FAST)
    assert decrypt_container(blob, password="pw")[0] == b""


@pytest.mark.parametrize("bad", [b"", b"nope", MAGIC + b"\x09" + bytes(100)])
def test_not_a_container(bad):
    with pytest.raises(ValueError):
        read_header(bad)


def test_password_or_key_required():
    with pytest.raises(ValueError):
        encrypt_container(b"x")
    with pytest.raises(ValueError):
        encrypt_container(b"x", password="a", hex_key="00" * 16)


# ------------------------------------------------------------------ text messages
def test_text_round_trip_unicode():
    msg = "Meet at 5pm ✓ — مرحبا"
    token = encrypt_text(msg, mode="OFB", password="pw", key_bits=192, **FAST)
    assert token.startswith("AESM1:")
    text, info = decrypt_text(token, password="pw")
    assert text == msg and info["mode"] == "OFB"


def test_text_rejects_garbage():
    with pytest.raises(ValueError):
        decrypt_text("hello", password="pw")
    with pytest.raises(ValueError):
        decrypt_text("AESM1:###", password="pw")


# ------------------------------------------------------------------ command line
def test_cli_round_trip(tmp_path):
    src = tmp_path / "photo.bin"
    src.write_bytes(os.urandom(5000))
    key = "ab" * 24
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parent.parent)}
    run = lambda *a: subprocess.run([sys.executable, "-m", "aesmodes.filecrypt", *a],
                                    capture_output=True, text=True, cwd=tmp_path, env=env)
    r = run("encrypt", str(src), "--key", key, "--mode", "CTR", "--counter", "1")
    assert r.returncode == 0, r.stderr
    out = tmp_path / "back.bin"
    r = run("decrypt", str(src) + ".aesm", "--key", key, "-o", str(out))
    assert r.returncode == 0, r.stderr
    assert out.read_bytes() == src.read_bytes()
    r = run("decrypt", str(src) + ".aesm", "--key", "cd" * 24, "-o", str(out))
    assert r.returncode == 1 and "Wrong password or key" in r.stderr


def test_pure_python_pbkdf2_matches_hashlib(monkeypatch):
    """The fallback used in the browser gives exactly hashlib's bytes."""
    import hashlib
    from aesmodes import filecrypt
    want = [hashlib.pbkdf2_hmac("sha256", b"pw", b"salt" * 4, 1000, dklen=n) for n in (32, 48, 64)]
    monkeypatch.delattr(hashlib, "pbkdf2_hmac")
    got = [filecrypt.pbkdf2_sha256(b"pw", b"salt" * 4, 1000, n) for n in (32, 48, 64)]
    assert got == want
    # RFC 7914 section 11 test vector for PBKDF2-HMAC-SHA256
    assert filecrypt.pbkdf2_sha256(b"passwd", b"salt", 1, 64).hex().startswith("55ac046e56e3089fec1691c22544b605")
