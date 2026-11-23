"""
Tests for AES-192 and AES-256 (the core, all five modes, and the app server).

Reference vectors:
  FIPS-197 Appendix A.2 / A.3  - key expansion for 192- and 256-bit keys
  FIPS-197 Appendix C.1-C.3    - one-block examples for all three key sizes
  NIST SP 800-38A Appendix F   - first block of every mode with AES-192 and AES-256
"""

import os

import pytest

from aesmodes import AES, decrypt, encrypt
from aesmodes.aes_core import KEY_SIZES, key_expansion
from aesmodes.modes import (
    MODE_NAMES,
    cbc_encrypt,
    cfb_encrypt,
    ctr_encrypt,
    ecb_encrypt,
    ofb_encrypt,
)
from aesmodes.padding import pad

PT_C = bytes.fromhex("00112233445566778899aabbccddeeff")
K192 = bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
K256 = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
NIST_IV = bytes(range(16))
NIST_P1 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
NIST_CTR = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"


# ------------------------------------------------------------ parameters
@pytest.mark.parametrize("n_bytes, nk, nr, words", [(16, 4, 10, 44), (24, 6, 12, 52), (32, 8, 14, 60)])
def test_key_size_parameters(n_bytes, nk, nr, words):
    aes = AES(os.urandom(n_bytes))
    assert (aes.nk, aes.nr, aes.key_bits) == (nk, nr, 8 * n_bytes)
    assert len(aes.w) == words and len(aes.round_keys) == nr + 1
    assert KEY_SIZES[n_bytes] == (nk, nr)


@pytest.mark.parametrize("n_bytes", [0, 8, 15, 17, 20, 31, 33, 64])
def test_invalid_key_lengths_rejected(n_bytes):
    with pytest.raises(ValueError):
        AES(bytes(n_bytes))
    with pytest.raises(ValueError):
        encrypt("CBC", bytes(n_bytes), b"hello")


# ------------------------------------------------------------ key expansion
def test_key_expansion_aes192_fips197_a2():
    w = key_expansion(K192)
    assert bytes(w[6]).hex() == "fe0c91f7"       # first word computed with RotWord/SubWord/Rcon
    assert bytes(w[51]).hex() == "01002202"


def test_key_expansion_aes256_fips197_a3():
    w = key_expansion(K256)
    assert bytes(w[8]).hex() == "9ba35411"
    assert bytes(w[12]).hex() == "a8b09c1a"      # the extra SubWord step (i % 8 == 4)
    assert bytes(w[59]).hex() == "706c631e"


# ------------------------------------------------------------ one block
@pytest.mark.parametrize("n_bytes, expected", [
    (16, "69c4e0d86a7b0430d8cdb78070b4c55a"),    # FIPS-197 C.1
    (24, "dda97ca4864cdfe06eaf70a0ec0d7191"),    # FIPS-197 C.2
    (32, "8ea2b7ca516745bfeafc49904b496089"),    # FIPS-197 C.3
])
def test_fips197_appendix_c(n_bytes, expected):
    aes = AES(bytes(range(n_bytes)))
    ct = aes.encrypt_block(PT_C)
    assert ct.hex() == expected
    assert aes.decrypt_block(ct) == PT_C


@pytest.mark.parametrize("n_bytes", [24, 32])
def test_random_blocks_match_pycryptodome(n_bytes):
    ref = pytest.importorskip("Crypto.Cipher.AES")
    for _ in range(100):
        key, block = os.urandom(n_bytes), os.urandom(16)
        aes = AES(key)
        assert aes.encrypt_block(block) == ref.new(key, ref.MODE_ECB).encrypt(block)
        assert aes.decrypt_block(aes.encrypt_block(block)) == block


# ------------------------------------------------------------ the five modes
NIST_FIRST_BLOCK = {
    ("ECB", 192): "bd334f1d6e45f25ff712a214571fa5cc", ("ECB", 256): "f3eed1bdb5d2a03c064b5a7e3db181f8",
    ("CBC", 192): "4f021db243bc633d7178183a9fa071e8", ("CBC", 256): "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
    ("CFB", 192): "cdc80d6fddf18cab34c25909c99a4174", ("CFB", 256): "dc7e84bfda79164b7ecd8486985d3860",
    ("OFB", 192): "cdc80d6fddf18cab34c25909c99a4174", ("OFB", 256): "dc7e84bfda79164b7ecd8486985d3860",
    ("CTR", 192): "1abc932417521ca24f2b0459fe7e6e0b", ("CTR", 256): "601ec313775789a5b7a7f504bbf3d228",
}


@pytest.mark.parametrize("mode, bits", list(NIST_FIRST_BLOCK))
def test_nist_sp800_38a_first_block(mode, bits):
    key = K192 if bits == 192 else K256
    if mode == "ECB":
        out = ecb_encrypt(key, NIST_P1)
    elif mode == "CTR":
        out = ctr_encrypt(key, NIST_P1, NIST_CTR)
    else:
        out = {"CBC": cbc_encrypt, "CFB": cfb_encrypt, "OFB": ofb_encrypt}[mode](key, NIST_P1, NIST_IV)
    assert out.output[:16].hex() == NIST_FIRST_BLOCK[(mode, bits)]


@pytest.mark.parametrize("mode", MODE_NAMES)
@pytest.mark.parametrize("n_bytes", [24, 32])
@pytest.mark.parametrize("length", [0, 1, 16, 33])
def test_round_trip_all_modes(mode, n_bytes, length):
    key, msg = os.urandom(n_bytes), os.urandom(length)
    ct = encrypt(mode, key, msg, counter="2a")
    assert decrypt(mode, key, ct.output, counter="2a").output == msg


@pytest.mark.parametrize("n_bytes", [24, 32])
def test_modes_match_pycryptodome_zero_iv(n_bytes):
    R = pytest.importorskip("Crypto.Cipher.AES")
    key, msg = os.urandom(n_bytes), os.urandom(50)
    data, iv = pad(msg), bytes(16)
    assert encrypt("ECB", key, msg).output == R.new(key, R.MODE_ECB).encrypt(data)
    assert encrypt("CBC", key, msg).output == R.new(key, R.MODE_CBC, iv=iv).encrypt(data)
    assert encrypt("CFB", key, msg).output == R.new(key, R.MODE_CFB, iv=iv, segment_size=128).encrypt(data)
    assert encrypt("OFB", key, msg).output == R.new(key, R.MODE_OFB, iv=iv).encrypt(data)
    assert encrypt("CTR", key, msg, counter=7).output == \
        R.new(key, R.MODE_CTR, nonce=b"", initial_value=7).encrypt(data)


def test_different_key_sizes_give_different_ciphertexts():
    outs = {encrypt("CBC", bytes(n), b"same message").output for n in (16, 24, 32)}
    assert len(outs) == 3


# ------------------------------------------------------------ the app server
@pytest.fixture()
def client():
    pytest.importorskip("flask")
    from aesmodes.web import create_app
    return create_app().test_client()


@pytest.mark.parametrize("n_bytes, rounds, steps, words", [(16, 10, 41, 44), (24, 12, 49, 52), (32, 14, 57, 60)])
def test_server_aes_walkthrough(client, n_bytes, rounds, steps, words):
    r = client.post("/api/aes", json={"key": bytes(range(n_bytes)).hex(), "block": PT_C.hex()}).get_json()
    assert r["rounds"] == rounds and r["keyBits"] == 8 * n_bytes
    assert len(r["steps"]) == steps and len(r["keyExpansion"]) == words
    assert r["ciphertext"] == AES(bytes(range(n_bytes))).encrypt_block(PT_C).hex()


def test_server_key_expansion_aes256_has_extra_subword(client):
    w = client.post("/api/keys", json={"key": K256.hex()}).get_json()["keyExpansion"]
    assert [x["kind"] for x in w[8:16]] == ["g", "xor", "xor", "xor", "h", "xor", "xor", "xor"]
    assert w[12]["word"] == "a8b09c1a"


def test_server_rejects_odd_key_length(client):
    r = client.post("/api/mode", json={"mode": "ECB", "operation": "encrypt", "key": "00" * 20, "data": "x"})
    assert r.status_code == 400 and "32, 48 or 64" in r.get_json()["error"]


@pytest.mark.parametrize("mode", MODE_NAMES)
def test_server_modes_aes256(client, mode):
    key = K256.hex()
    enc = client.post("/api/mode", json={"mode": mode, "operation": "encrypt", "key": key,
                                         "data": "AES-256 works too", "counter": "1"}).get_json()
    assert enc["keyBits"] == 256
    dec = client.post("/api/mode", json={"mode": mode, "operation": "decrypt", "key": key,
                                         "data": enc["output"], "counter": "1"}).get_json()
    assert dec["outputText"] == "AES-256 works too"
