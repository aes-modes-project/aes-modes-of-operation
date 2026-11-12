"""
aes_core.py - AES-128 block cipher (FIPS-197), implemented from scratch.

EECE 455/632 - Project 8: AES in 5 modes of operation.

This module encrypts / decrypts exactly ONE 16-byte block.
The modes of operation (ECB, CBC, CFB, OFB, CTR) are built on top of it.

Every encrypt/decrypt call can optionally record a *trace* (a list of the
intermediate states) so the GUI can show the cipher step by step.

State layout (as in FIPS-197): the 16 input bytes fill a 4x4 matrix
column by column, i.e.  state[row][col] = block[row + 4*col].
"""

from typing import List, Optional

NB = 4    # number of columns in the state
NK = 4    # number of 32-bit words in the key (AES-128)
NR = 10   # number of rounds (AES-128)

State = List[List[int]]   # 4x4 matrix of bytes
Word = List[int]          # 4 bytes


# --------------------------------------------------------------------------
# GF(2^8) arithmetic  (irreducible polynomial m(x) = x^8 + x^4 + x^3 + x + 1)
# --------------------------------------------------------------------------
def xtime(a: int) -> int:
    """Multiply by x (i.e. by 0x02) in GF(2^8)."""
    a <<= 1
    return (a ^ 0x11B) if a & 0x100 else a


def gmul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8)."""
    p = 0
    while b:
        if b & 1:
            p ^= a
        a = xtime(a)
        b >>= 1
    return p


def ginv(a: int) -> int:
    """Multiplicative inverse in GF(2^8): a^254 (0 maps to 0)."""
    if a == 0:
        return 0
    result, base, e = 1, a, 254
    while e:
        if e & 1:
            result = gmul(result, base)
        base = gmul(base, base)
        e >>= 1
    return result


def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _affine(b: int) -> int:
    """S-box affine transformation: b ^ rotl(b,1..4) ^ 0x63."""
    return b ^ _rotl8(b, 1) ^ _rotl8(b, 2) ^ _rotl8(b, 3) ^ _rotl8(b, 4) ^ 0x63


# The S-box is *computed* from its mathematical definition
# (inverse in GF(2^8) followed by the affine map) instead of being typed in,
# which removes any risk of a typo in a 256-entry table.
SBOX = [_affine(ginv(x)) for x in range(256)]
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

# Round constants Rcon[i] = x^(i-1) in GF(2^8)
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


# --------------------------------------------------------------------------
# Conversions
# --------------------------------------------------------------------------
def bytes_to_state(block: bytes) -> State:
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def state_to_bytes(s: State) -> bytes:
    return bytes(s[r][c] for c in range(4) for r in range(4))


def state_to_hex(s: State) -> str:
    return state_to_bytes(s).hex()


def copy_state(s: State) -> State:
    return [row[:] for row in s]


def format_state(s: State) -> str:
    """Pretty 4x4 matrix, e.g. for printing a trace."""
    return "\n".join(" ".join(f"{b:02x}" for b in row) for row in s)


# --------------------------------------------------------------------------
# Key expansion
# --------------------------------------------------------------------------
def rot_word(w: Word) -> Word:
    return w[1:] + w[:1]


def sub_word(w: Word) -> Word:
    return [SBOX[b] for b in w]


def key_expansion(key: bytes) -> List[Word]:
    """Expand a 16-byte key into 44 words w[0..43] (11 round keys)."""
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes (32 hex digits).")
    w: List[Word] = [list(key[4 * i: 4 * i + 4]) for i in range(NK)]
    for i in range(NK, NB * (NR + 1)):
        temp = w[i - 1][:]
        if i % NK == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i // NK - 1]
        w.append([w[i - NK][j] ^ temp[j] for j in range(4)])
    return w


def round_key_state(w: List[Word], rnd: int) -> State:
    """Round key `rnd` (words 4*rnd .. 4*rnd+3) as a 4x4 state matrix."""
    return [[w[4 * rnd + c][r] for c in range(4)] for r in range(4)]


# --------------------------------------------------------------------------
# Round operations
# --------------------------------------------------------------------------
def sub_bytes(s: State) -> State:
    return [[SBOX[b] for b in row] for row in s]


def inv_sub_bytes(s: State) -> State:
    return [[INV_SBOX[b] for b in row] for row in s]


def shift_rows(s: State) -> State:
    # row r is rotated left by r positions
    return [s[r][r:] + s[r][:r] for r in range(4)]


def inv_shift_rows(s: State) -> State:
    # row r is rotated right by r positions
    return [s[r][4 - r:] + s[r][:4 - r] for r in range(4)]


_MIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
_INV_MIX = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]


def _mix(s: State, m: List[List[int]]) -> State:
    out = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [s[r][c] for r in range(4)]
        for r in range(4):
            v = 0
            for k in range(4):
                v ^= gmul(m[r][k], col[k])
            out[r][c] = v
    return out


def mix_columns(s: State) -> State:
    return _mix(s, _MIX)


def inv_mix_columns(s: State) -> State:
    return _mix(s, _INV_MIX)


def add_round_key(s: State, k: State) -> State:
    return [[s[r][c] ^ k[r][c] for c in range(4)] for r in range(4)]


# --------------------------------------------------------------------------
# The cipher
# --------------------------------------------------------------------------
class AES128:
    """
    AES-128 block cipher.

        aes = AES128(key_bytes)
        ct  = aes.encrypt_block(pt_block)
        pt  = aes.decrypt_block(ct_block)

    Pass a list as `trace=` to collect every intermediate state:
    each entry is a dict {"round": int, "step": str, "state": State}.
    """

    def __init__(self, key: bytes):
        self.key = bytes(key)
        self.w = key_expansion(self.key)
        self.round_keys = [round_key_state(self.w, r) for r in range(NR + 1)]

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _log(trace: Optional[list], rnd: int, step: str, s: State) -> None:
        if trace is not None:
            trace.append({"round": rnd, "step": step, "state": copy_state(s)})

    @staticmethod
    def _check(block: bytes) -> None:
        if len(block) != 16:
            raise ValueError("AES block must be exactly 16 bytes.")

    # -- encryption --------------------------------------------------------
    def encrypt_block(self, block: bytes, trace: Optional[list] = None) -> bytes:
        self._check(block)
        rk = self.round_keys
        s = bytes_to_state(block)
        self._log(trace, 0, "Input", s)

        s = add_round_key(s, rk[0])
        self._log(trace, 0, "AddRoundKey", s)

        for rnd in range(1, NR + 1):
            s = sub_bytes(s)
            self._log(trace, rnd, "SubBytes", s)
            s = shift_rows(s)
            self._log(trace, rnd, "ShiftRows", s)
            if rnd != NR:                       # no MixColumns in final round
                s = mix_columns(s)
                self._log(trace, rnd, "MixColumns", s)
            s = add_round_key(s, rk[rnd])
            self._log(trace, rnd, "AddRoundKey", s)

        return state_to_bytes(s)

    # -- decryption (inverse cipher, FIPS-197 sec. 5.3) --------------------
    def decrypt_block(self, block: bytes, trace: Optional[list] = None) -> bytes:
        self._check(block)
        rk = self.round_keys
        s = bytes_to_state(block)
        self._log(trace, 0, "Input", s)

        s = add_round_key(s, rk[NR])
        self._log(trace, 0, "AddRoundKey", s)

        for rnd in range(1, NR + 1):
            s = inv_shift_rows(s)
            self._log(trace, rnd, "InvShiftRows", s)
            s = inv_sub_bytes(s)
            self._log(trace, rnd, "InvSubBytes", s)
            s = add_round_key(s, rk[NR - rnd])
            self._log(trace, rnd, "AddRoundKey", s)
            if rnd != NR:                       # no InvMixColumns in final round
                s = inv_mix_columns(s)
                self._log(trace, rnd, "InvMixColumns", s)

        return state_to_bytes(s)
