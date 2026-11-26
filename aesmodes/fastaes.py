"""
fastaes.py - a fast AES block cipher using lookup tables ("T-tables").

aes_core.py is written to be easy to follow: it keeps the state as a 4x4 grid
and applies SubBytes, ShiftRows, MixColumns and AddRoundKey one at a time, so
the learning app can show every step. That costs time.

This module computes exactly the same cipher, faster, for the file encryptor:
each column of the state is one 32-bit word, and SubBytes + ShiftRows +
MixColumns of a round are merged into four table lookups per column:

    Te0[x] = ( 02*S[x],  S[x],    S[x],   03*S[x] )      one column of MixColumns
    Te1, Te2, Te3 = Te0 rotated by 8, 16, 24 bits         applied to the S-box output

    new column j = Te0[s_j row0] ^ Te1[s_{j+1} row1] ^ Te2[s_{j+2} row2] ^ Te3[s_{j+3} row3] ^ k_j

(the shifted indices j+1, j+2, j+3 are ShiftRows). Decryption uses the inverse
tables Td0..Td3 built from the inverse S-box and InvMixColumns, with the round
keys passed through InvMixColumns ("equivalent inverse cipher", FIPS-197 5.3.5).

All tables are computed here from the project's own S-box and GF(2^8)
multiplication (aes_core.SBOX, aes_core.gmul); nothing is copied from elsewhere.
tests/test_filecrypt.py checks that every result equals aes_core.AES.
"""

from typing import List

from .aes_core import INV_SBOX, SBOX, gmul, key_expansion, key_params


def _word(b0: int, b1: int, b2: int, b3: int) -> int:
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3


def _ror8(w: int) -> int:
    return ((w >> 8) | (w << 24)) & 0xFFFFFFFF


def _tables(sbox, coefs):
    t0 = [_word(*(gmul(c, sbox[x]) for c in coefs)) for x in range(256)]
    t1 = [_ror8(w) for w in t0]
    t2 = [_ror8(w) for w in t1]
    t3 = [_ror8(w) for w in t2]
    return t0, t1, t2, t3


TE0, TE1, TE2, TE3 = _tables(SBOX, (2, 1, 1, 3))
TD0, TD1, TD2, TD3 = _tables(INV_SBOX, (14, 9, 13, 11))


def _inv_mix_word(w: int) -> int:
    """InvMixColumns of one column word (Td tables include the inverse S-box, so undo it with SBOX)."""
    return (TD0[SBOX[w >> 24]] ^ TD1[SBOX[(w >> 16) & 255]]
            ^ TD2[SBOX[(w >> 8) & 255]] ^ TD3[SBOX[w & 255]])


class FastAES:
    """Same interface as aes_core.AES for whole blocks: encrypt_block / decrypt_block."""

    def __init__(self, key: bytes):
        self.nk, self.nr = key_params(key)
        words = [_word(*w) for w in key_expansion(bytes(key))]
        self.ek: List[int] = words
        nr = self.nr
        dk = words[4 * nr: 4 * nr + 4]
        for r in range(nr - 1, 0, -1):
            dk += [_inv_mix_word(w) for w in words[4 * r: 4 * r + 4]]
        dk += words[0:4]
        self.dk: List[int] = dk

    def encrypt_block(self, block: bytes) -> bytes:
        k, t0, t1, t2, t3 = self.ek, TE0, TE1, TE2, TE3
        v = int.from_bytes(block, "big")
        s0 = (v >> 96) ^ k[0]
        s1 = ((v >> 64) & 0xFFFFFFFF) ^ k[1]
        s2 = ((v >> 32) & 0xFFFFFFFF) ^ k[2]
        s3 = (v & 0xFFFFFFFF) ^ k[3]
        i = 4
        for _ in range(self.nr - 1):
            s0, s1, s2, s3 = (
                t0[s0 >> 24] ^ t1[(s1 >> 16) & 255] ^ t2[(s2 >> 8) & 255] ^ t3[s3 & 255] ^ k[i],
                t0[s1 >> 24] ^ t1[(s2 >> 16) & 255] ^ t2[(s3 >> 8) & 255] ^ t3[s0 & 255] ^ k[i + 1],
                t0[s2 >> 24] ^ t1[(s3 >> 16) & 255] ^ t2[(s0 >> 8) & 255] ^ t3[s1 & 255] ^ k[i + 2],
                t0[s3 >> 24] ^ t1[(s0 >> 16) & 255] ^ t2[(s1 >> 8) & 255] ^ t3[s2 & 255] ^ k[i + 3],
            )
            i += 4
        S = SBOX                                   # final round: no MixColumns
        o0 = _word(S[s0 >> 24], S[(s1 >> 16) & 255], S[(s2 >> 8) & 255], S[s3 & 255]) ^ k[i]
        o1 = _word(S[s1 >> 24], S[(s2 >> 16) & 255], S[(s3 >> 8) & 255], S[s0 & 255]) ^ k[i + 1]
        o2 = _word(S[s2 >> 24], S[(s3 >> 16) & 255], S[(s0 >> 8) & 255], S[s1 & 255]) ^ k[i + 2]
        o3 = _word(S[s3 >> 24], S[(s0 >> 16) & 255], S[(s1 >> 8) & 255], S[s2 & 255]) ^ k[i + 3]
        return ((o0 << 96) | (o1 << 64) | (o2 << 32) | o3).to_bytes(16, "big")

    def decrypt_block(self, block: bytes) -> bytes:
        k, t0, t1, t2, t3 = self.dk, TD0, TD1, TD2, TD3
        v = int.from_bytes(block, "big")
        s0 = (v >> 96) ^ k[0]
        s1 = ((v >> 64) & 0xFFFFFFFF) ^ k[1]
        s2 = ((v >> 32) & 0xFFFFFFFF) ^ k[2]
        s3 = (v & 0xFFFFFFFF) ^ k[3]
        i = 4
        for _ in range(self.nr - 1):               # InvShiftRows moves bytes the other way
            s0, s1, s2, s3 = (
                t0[s0 >> 24] ^ t1[(s3 >> 16) & 255] ^ t2[(s2 >> 8) & 255] ^ t3[s1 & 255] ^ k[i],
                t0[s1 >> 24] ^ t1[(s0 >> 16) & 255] ^ t2[(s3 >> 8) & 255] ^ t3[s2 & 255] ^ k[i + 1],
                t0[s2 >> 24] ^ t1[(s1 >> 16) & 255] ^ t2[(s0 >> 8) & 255] ^ t3[s3 & 255] ^ k[i + 2],
                t0[s3 >> 24] ^ t1[(s2 >> 16) & 255] ^ t2[(s1 >> 8) & 255] ^ t3[s0 & 255] ^ k[i + 3],
            )
            i += 4
        S = INV_SBOX
        o0 = _word(S[s0 >> 24], S[(s3 >> 16) & 255], S[(s2 >> 8) & 255], S[s1 & 255]) ^ k[i]
        o1 = _word(S[s1 >> 24], S[(s0 >> 16) & 255], S[(s3 >> 8) & 255], S[s2 & 255]) ^ k[i + 1]
        o2 = _word(S[s2 >> 24], S[(s1 >> 16) & 255], S[(s0 >> 8) & 255], S[s3 & 255]) ^ k[i + 2]
        o3 = _word(S[s3 >> 24], S[(s2 >> 16) & 255], S[(s1 >> 8) & 255], S[s0 & 255]) ^ k[i + 3]
        return ((o0 << 96) | (o1 << 64) | (o2 << 32) | o3).to_bytes(16, "big")
