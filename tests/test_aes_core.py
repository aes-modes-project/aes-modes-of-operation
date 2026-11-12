"""
Tests for the AES-128 core (aesmodes/aes_core.py).

Run from the repository root:
    python -m pytest -v

Test vectors come from FIPS-197 (the official AES standard):
  - Appendix A.1 : key expansion
  - Appendix B   : cipher example
  - Appendix C.1 : AES-128 example vector
"""

import os

import pytest

from aesmodes.aes_core import (
    AES128,
    INV_SBOX,
    SBOX,
    inv_mix_columns,
    inv_shift_rows,
    mix_columns,
    shift_rows,
    bytes_to_state,
)

FIPS_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


# ----------------------------------------------------------------- S-box
def test_sbox_known_values():
    assert SBOX[0x00] == 0x63
    assert SBOX[0x01] == 0x7C
    assert SBOX[0x53] == 0xED          # FIPS-197 section 5.1.1 example


def test_inverse_sbox_undoes_sbox():
    assert all(INV_SBOX[SBOX[x]] == x for x in range(256))


def test_sbox_is_a_permutation():
    assert sorted(SBOX) == list(range(256))


# --------------------------------------------------------- key expansion
def test_key_expansion_fips197_a1():
    w = AES128(FIPS_KEY).w
    assert len(w) == 44
    assert bytes(w[4]).hex() == "a0fafe17"
    assert bytes(w[10]).hex() == "5935807a"
    assert bytes(w[43]).hex() == "b6630ca6"


def test_wrong_key_length_rejected():
    with pytest.raises(ValueError):
        AES128(b"short key")


# ------------------------------------------------- round operations inverses
def test_inverse_round_operations():
    s = bytes_to_state(os.urandom(16))
    assert inv_shift_rows(shift_rows(s)) == s
    assert inv_mix_columns(mix_columns(s)) == s


# ------------------------------------------------------- full block cipher
def test_encrypt_fips197_appendix_b():
    ct = AES128(FIPS_KEY).encrypt_block(bytes.fromhex("3243f6a8885a308d313198a2e0370734"))
    assert ct.hex() == "3925841d02dc09fbdc118597196a0b32"


def test_encrypt_decrypt_fips197_appendix_c1():
    aes = AES128(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = aes.encrypt_block(pt)
    assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
    assert aes.decrypt_block(ct) == pt


def test_wrong_block_length_rejected():
    with pytest.raises(ValueError):
        AES128(FIPS_KEY).encrypt_block(b"15 bytes only!!")


# ------------------------------------------------------------------ trace
def test_encryption_trace_structure():
    trace = []
    AES128(FIPS_KEY).encrypt_block(bytes.fromhex("3243f6a8885a308d313198a2e0370734"), trace)
    # Input + initial AddRoundKey + 9 rounds * 4 steps + final round * 3 steps
    assert len(trace) == 2 + 9 * 4 + 3
    assert trace[-1]["round"] == 10 and trace[-1]["step"] == "AddRoundKey"
    # FIPS-197 Appendix B: state at start of round 1 (after initial AddRoundKey)
    first = trace[1]["state"]
    assert [first[r][0] for r in range(4)] == [0x19, 0x3D, 0xE3, 0xBE]


# ------------------------------------------------- random + reference check
def test_random_round_trips():
    for _ in range(200):
        aes = AES128(os.urandom(16))
        block = os.urandom(16)
        assert aes.decrypt_block(aes.encrypt_block(block)) == block


def test_matches_pycryptodome():
    ref = pytest.importorskip("Crypto.Cipher.AES")
    for _ in range(200):
        key, block = os.urandom(16), os.urandom(16)
        expected = ref.new(key, ref.MODE_ECB).encrypt(block)
        assert AES128(key).encrypt_block(block) == expected
