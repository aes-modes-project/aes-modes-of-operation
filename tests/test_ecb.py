"""
Tests for ECB mode.

Reference vectors: NIST SP 800-38A, Appendix F.1.1 (ECB-AES128.Encrypt).
NIST's vectors use no padding, so we compare the first 64 bytes of our output;
our version then appends one extra block of padding (64 bytes is block-aligned).
"""

import os

import pytest

from aesmodes.modes import ecb_decrypt, ecb_encrypt, split_blocks
from aesmodes.padding import pad

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
PT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
CT = bytes.fromhex(
    "3ad77bb40d7a3660a89ecaf32466ef97"
    "f5d3d58503b9699de785895a96fdbaaf"
    "43b1cd7f598ece23881b00e3ed030688"
    "7b0c785e27e8ad3f8223207104725dd4"
)


def test_nist_sp800_38a_f11():
    res = ecb_encrypt(KEY, PT)
    assert res.output[:64] == CT
    assert len(res.output) == 80                 # + one full padding block
    assert len(res.steps) == 5


def test_decrypt_round_trip():
    res = ecb_encrypt(KEY, PT)
    assert ecb_decrypt(KEY, res.output).output == PT


@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 33, 100])
def test_random_round_trips(length):
    key, msg = os.urandom(16), os.urandom(length)
    assert ecb_decrypt(key, ecb_encrypt(key, msg).output).output == msg


def test_identical_blocks_give_identical_ciphertext():
    """The well-known ECB weakness: patterns in the plaintext survive."""
    msg = b"YELLOW SUBMARINE" * 3
    blocks = split_blocks(ecb_encrypt(KEY, msg).output)
    assert blocks[0] == blocks[1] == blocks[2]


def test_matches_pycryptodome():
    ref = pytest.importorskip("Crypto.Cipher.AES")
    key, msg = os.urandom(16), os.urandom(77)
    expected = ref.new(key, ref.MODE_ECB).encrypt(pad(msg))
    assert ecb_encrypt(key, msg).output == expected


def test_bad_ciphertext_length_rejected():
    with pytest.raises(ValueError):
        ecb_decrypt(KEY, b"\x00" * 20)


def test_bad_key_length_rejected():
    with pytest.raises(ValueError):
        ecb_encrypt(b"\x00" * 10, b"hi")
