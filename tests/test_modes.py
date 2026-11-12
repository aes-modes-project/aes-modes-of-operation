"""
Tests for CBC, CFB, OFB and CTR modes.

Reference vectors: NIST SP 800-38A, Appendix F (AES-128):
    F.2.1 CBC-AES128.Encrypt     F.3.13 CFB128-AES128.Encrypt
    F.4.1 OFB-AES128.Encrypt     F.5.1  CTR-AES128.Encrypt

NIST uses the IV 000102...0f and no padding. Our functions accept `iv=` for
exactly this purpose; the application itself always uses the zero IV.
Because the 64-byte NIST plaintext is block-aligned, our output has one extra
padding block, so we compare the first 64 bytes.
"""

import os

import pytest

from aesmodes.modes import (
    MODE_NAMES,
    ZERO_IV,
    cbc_decrypt,
    cbc_encrypt,
    cfb_decrypt,
    cfb_encrypt,
    counter_block,
    counter_to_int,
    ctr_decrypt,
    ctr_encrypt,
    decrypt,
    encrypt,
    ofb_decrypt,
    ofb_encrypt,
    split_blocks,
)
from aesmodes.padding import pad

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
NIST_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
NIST_CTR = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
PT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
NIST = {
    "CBC": "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
           "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
    "CFB": "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"
           "26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6",
    "OFB": "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825"
           "9740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e",
    "CTR": "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
           "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
}


# ------------------------------------------------------------ NIST vectors
def test_cbc_nist_f21():
    assert cbc_encrypt(KEY, PT, NIST_IV).output[:64].hex() == NIST["CBC"]


def test_cfb_nist_f313():
    assert cfb_encrypt(KEY, PT, NIST_IV).output[:64].hex() == NIST["CFB"]


def test_ofb_nist_f41():
    assert ofb_encrypt(KEY, PT, NIST_IV).output[:64].hex() == NIST["OFB"]


def test_ctr_nist_f51():
    assert ctr_encrypt(KEY, PT, NIST_CTR).output[:64].hex() == NIST["CTR"]


def test_nist_vectors_decrypt():
    assert cbc_decrypt(KEY, cbc_encrypt(KEY, PT, NIST_IV).output, NIST_IV).output == PT
    assert cfb_decrypt(KEY, cfb_encrypt(KEY, PT, NIST_IV).output, NIST_IV).output == PT
    assert ofb_decrypt(KEY, ofb_encrypt(KEY, PT, NIST_IV).output, NIST_IV).output == PT
    assert ctr_decrypt(KEY, ctr_encrypt(KEY, PT, NIST_CTR).output, NIST_CTR).output == PT


# --------------------------------------------- zero IV (project specification)
def test_default_iv_is_zero():
    for fn in (cbc_encrypt, cfb_encrypt, ofb_encrypt):
        assert fn(KEY, b"hello").iv == ZERO_IV
    assert cbc_encrypt(KEY, b"hello").output == cbc_encrypt(KEY, b"hello", bytes(16)).output


# ------------------------------------------------ round trips, all modes
@pytest.mark.parametrize("mode", MODE_NAMES)
@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 32, 100])
def test_round_trip_all_modes(mode, length):
    key, msg = os.urandom(16), os.urandom(length)
    ctr = os.urandom(16).hex()
    ct = encrypt(mode, key, msg, counter=ctr)
    assert len(ct.output) % 16 == 0 and len(ct.output) > len(msg)
    assert decrypt(mode, key, ct.output, counter=ctr).output == msg


# --------------------------------------------- comparison with pycryptodome
@pytest.mark.parametrize("mode", ["CBC", "CFB", "OFB", "CTR"])
def test_matches_pycryptodome_zero_iv(mode):
    AES = pytest.importorskip("Crypto.Cipher.AES")
    key, msg = os.urandom(16), os.urandom(77)
    data = pad(msg)
    if mode == "CBC":
        ref = AES.new(key, AES.MODE_CBC, iv=ZERO_IV).encrypt(data)
        ours = cbc_encrypt(key, msg).output
    elif mode == "CFB":
        ref = AES.new(key, AES.MODE_CFB, iv=ZERO_IV, segment_size=128).encrypt(data)
        ours = cfb_encrypt(key, msg).output
    elif mode == "OFB":
        ref = AES.new(key, AES.MODE_OFB, iv=ZERO_IV).encrypt(data)
        ours = ofb_encrypt(key, msg).output
    else:
        start = int.from_bytes(os.urandom(16), "big")
        ref = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=start).encrypt(data)
        ours = ctr_encrypt(key, msg, start).output
    assert ours == ref


# -------------------------------------------------------- CTR counter rules
def test_counter_formats_are_equivalent():
    as_int = ctr_encrypt(KEY, b"abc", 0x1234).output
    assert ctr_encrypt(KEY, b"abc", "1234").output == as_int
    assert ctr_encrypt(KEY, b"abc", "0x1234").output == as_int
    assert ctr_encrypt(KEY, b"abc", (0x1234).to_bytes(16, "big")).output == as_int


def test_counter_increments_per_block():
    res = ctr_encrypt(KEY, bytes(40), 5)            # 40 bytes -> 3 blocks
    assert [int.from_bytes(s.aes_input, "big") for s in res.steps] == [5, 6, 7]


def test_counter_wraps_around_2_128():
    assert counter_block(2 ** 128 - 1, 1) == bytes(16)


@pytest.mark.parametrize("bad", ["", "xyz", "1" * 33, -1, 2 ** 128])
def test_invalid_counter_rejected(bad):
    with pytest.raises(ValueError):
        counter_to_int(bad)


def test_ctr_requires_counter():
    with pytest.raises(ValueError):
        encrypt("CTR", KEY, b"hi")


def test_unknown_mode_rejected():
    with pytest.raises(ValueError):
        encrypt("XTS", KEY, b"hi")


# ------------------------------------------- properties used in the report
def test_cbc_hides_repeated_blocks():
    msg = b"YELLOW SUBMARINE" * 3
    blocks = split_blocks(cbc_encrypt(KEY, msg).output)
    assert len(set(blocks[:3])) == 3


def test_zero_iv_is_deterministic():
    """Why a fixed IV is insecure: the same message always gives the same ciphertext."""
    assert cbc_encrypt(KEY, b"attack at dawn").output == cbc_encrypt(KEY, b"attack at dawn").output


def _flip_first_bit(data: bytes) -> bytes:
    return bytes([data[0] ^ 0x01]) + data[1:]


def _damaged_blocks(mode, msg, counter=1):
    ct = encrypt(mode, KEY, msg, counter=counter).output
    bad = decrypt(mode, KEY, _flip_first_bit(ct), counter=counter).padded
    good = pad(msg)
    return [i for i, (a, b) in enumerate(zip(split_blocks(good), split_blocks(bad))) if a != b]


MSG = bytes(range(64))      # 4 blocks of data + 1 padding block


def test_error_propagation_ecb():
    assert _damaged_blocks("ECB", MSG) == [0]          # only block 1 (fully garbled)


def test_error_propagation_cbc():
    assert _damaged_blocks("CBC", MSG) == [0, 1]       # block 1 garbled, 1 bit flipped in block 2


def test_error_propagation_cfb():
    assert _damaged_blocks("CFB", MSG) == [0, 1]       # 1 bit flipped in block 1, block 2 garbled


@pytest.mark.parametrize("mode", ["OFB", "CTR"])
def test_error_propagation_stream_modes(mode):
    assert _damaged_blocks(mode, MSG) == [0]           # exactly one bit flipped, nothing else


# ------------------------------------------------------------ step records
def test_steps_record_chaining():
    res = cbc_encrypt(KEY, bytes(40))
    assert res.steps[0].xor_with == ZERO_IV
    assert res.steps[1].xor_with == res.steps[0].block_out      # C_{i-1}
    assert all(s.note for s in res.steps)
