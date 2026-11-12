"""
modes.py - AES-128 modes of operation: ECB, CBC, CFB, OFB and CTR.

Every function returns a `ModeResult` containing the output bytes and one
`BlockStep` per block. A BlockStep records exactly what happened to that block
(what went into AES, what came out, what was XORed), so the GUI can display the
mode step by step.

Conventions (from the project specification):
    * key       : 16 bytes (AES-128)
    * padding   : zeros + pad-count byte (see padding.py), applied in ALL modes
    * IV        : 16 zero bytes for CBC / CFB / OFB
    * CTR       : initial counter chosen by the user, +1 per block (mod 2^128)

The `iv=` parameter exists only so the official NIST test vectors (which use a
non-zero IV) can be checked in the tests. The application always uses ZERO_IV.

Notation used in the comments:
    P_i plaintext block, C_i ciphertext block, E_K / D_K AES encrypt / decrypt,
    (+) XOR, IV = C_0 = O_0 = 00..00
"""

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Union

from .aes_core import AES128
from .padding import BLOCK_SIZE, pad, unpad

ZERO_IV = bytes(BLOCK_SIZE)
MODE_NAMES = ("ECB", "CBC", "CFB", "OFB", "CTR")


# --------------------------------------------------------------------------
# Result types
# --------------------------------------------------------------------------
@dataclass
class BlockStep:
    """What happened to one block."""
    index: int                        # block number, starting at 1
    block_in: bytes                   # plaintext block (encrypt) / ciphertext block (decrypt)
    aes_input: bytes                  # what was fed into AES
    aes_output: bytes                 # what AES produced
    block_out: bytes                  # resulting ciphertext / plaintext block
    xor_with: Optional[bytes] = None  # value XORed with the data (None for ECB)
    note: str = ""                    # the formula used for this block


@dataclass
class ModeResult:
    mode: str                         # "ECB", "CBC", ...
    operation: str                    # "encrypt" or "decrypt"
    output: bytes                     # ciphertext, or plaintext with padding removed
    padded: bytes                     # padded plaintext (encrypt) / decrypted text before unpadding
    steps: List[BlockStep] = field(default_factory=list)
    iv: Optional[bytes] = None        # IV used (CBC/CFB/OFB)
    counter: Optional[int] = None     # initial counter used (CTR)

    def hex(self) -> str:
        return self.output.hex()


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def split_blocks(data: bytes) -> List[bytes]:
    return [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def _check_key(key: bytes) -> None:
    if len(key) != 16:
        raise ValueError("Key must be exactly 16 bytes (32 hex digits) for AES-128.")


def _check_iv(iv: bytes) -> None:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be exactly 16 bytes.")


def _check_ciphertext(ct: bytes) -> None:
    if len(ct) == 0 or len(ct) % BLOCK_SIZE != 0:
        raise ValueError(
            f"Ciphertext length must be a positive multiple of {BLOCK_SIZE} bytes "
            f"(got {len(ct)})."
        )


def counter_to_int(counter: Union[int, bytes, str]) -> int:
    """Accept the initial counter as an int, 16 bytes, or a hex string (up to 32 digits)."""
    if isinstance(counter, int):
        value = counter
    elif isinstance(counter, (bytes, bytearray)):
        if len(counter) != BLOCK_SIZE:
            raise ValueError("Counter given as bytes must be exactly 16 bytes.")
        value = int.from_bytes(counter, "big")
    elif isinstance(counter, str):
        h = counter.strip().replace(" ", "")
        if h.lower().startswith("0x"):
            h = h[2:]
        if not h or len(h) > 32 or any(c not in "0123456789abcdefABCDEF" for c in h):
            raise ValueError("Counter must be 1 to 32 hex digits.")
        value = int(h, 16)
    else:
        raise TypeError("Counter must be an int, 16 bytes, or a hex string.")
    if not 0 <= value < 2 ** 128:
        raise ValueError("Counter must be between 0 and 2^128 - 1.")
    return value


def counter_block(initial: int, i: int) -> bytes:
    """T_i = (initial + i) mod 2^128, as a 16-byte big-endian block (i starts at 0)."""
    return ((initial + i) % (1 << 128)).to_bytes(BLOCK_SIZE, "big")


# --------------------------------------------------------------------------
# ECB - Electronic Codebook
#   C_i = E_K(P_i)          P_i = D_K(C_i)
# --------------------------------------------------------------------------
def ecb_encrypt(key: bytes, plaintext: bytes) -> ModeResult:
    _check_key(key)
    aes = AES128(key)
    padded = pad(plaintext)
    steps, out = [], b""
    for i, p in enumerate(split_blocks(padded), start=1):
        c = aes.encrypt_block(p)
        steps.append(BlockStep(i, p, p, c, c, note="C_i = E_K(P_i)"))
        out += c
    return ModeResult("ECB", "encrypt", out, padded, steps)


def ecb_decrypt(key: bytes, ciphertext: bytes) -> ModeResult:
    _check_key(key)
    _check_ciphertext(ciphertext)
    aes = AES128(key)
    steps, padded = [], b""
    for i, c in enumerate(split_blocks(ciphertext), start=1):
        p = aes.decrypt_block(c)
        steps.append(BlockStep(i, c, c, p, p, note="P_i = D_K(C_i)"))
        padded += p
    return ModeResult("ECB", "decrypt", unpad(padded), padded, steps)


# --------------------------------------------------------------------------
# CBC - Cipher Block Chaining
#   C_i = E_K(P_i (+) C_{i-1})      P_i = D_K(C_i) (+) C_{i-1}      C_0 = IV
# --------------------------------------------------------------------------
def cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes = ZERO_IV) -> ModeResult:
    _check_key(key)
    _check_iv(iv)
    aes = AES128(key)
    padded = pad(plaintext)
    steps, out, prev = [], b"", iv
    for i, p in enumerate(split_blocks(padded), start=1):
        x = xor_bytes(p, prev)
        c = aes.encrypt_block(x)
        steps.append(BlockStep(i, p, x, c, c, xor_with=prev,
                               note="C_i = E_K(P_i ⊕ C_{i-1})"))
        out += c
        prev = c
    return ModeResult("CBC", "encrypt", out, padded, steps, iv=iv)


def cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes = ZERO_IV) -> ModeResult:
    _check_key(key)
    _check_iv(iv)
    _check_ciphertext(ciphertext)
    aes = AES128(key)
    steps, padded, prev = [], b"", iv
    for i, c in enumerate(split_blocks(ciphertext), start=1):
        d = aes.decrypt_block(c)
        p = xor_bytes(d, prev)
        steps.append(BlockStep(i, c, c, d, p, xor_with=prev,
                               note="P_i = D_K(C_i) ⊕ C_{i-1}"))
        padded += p
        prev = c
    return ModeResult("CBC", "decrypt", unpad(padded), padded, steps, iv=iv)


# --------------------------------------------------------------------------
# CFB - Cipher Feedback (full-block, s = 128 bits)
#   C_i = P_i (+) E_K(C_{i-1})      P_i = C_i (+) E_K(C_{i-1})      C_0 = IV
#   Note: decryption also uses AES *encryption*.
# --------------------------------------------------------------------------
def cfb_encrypt(key: bytes, plaintext: bytes, iv: bytes = ZERO_IV) -> ModeResult:
    _check_key(key)
    _check_iv(iv)
    aes = AES128(key)
    padded = pad(plaintext)
    steps, out, prev = [], b"", iv
    for i, p in enumerate(split_blocks(padded), start=1):
        o = aes.encrypt_block(prev)
        c = xor_bytes(p, o)
        steps.append(BlockStep(i, p, prev, o, c, xor_with=o,
                               note="C_i = P_i ⊕ E_K(C_{i-1})"))
        out += c
        prev = c
    return ModeResult("CFB", "encrypt", out, padded, steps, iv=iv)


def cfb_decrypt(key: bytes, ciphertext: bytes, iv: bytes = ZERO_IV) -> ModeResult:
    _check_key(key)
    _check_iv(iv)
    _check_ciphertext(ciphertext)
    aes = AES128(key)
    steps, padded, prev = [], b"", iv
    for i, c in enumerate(split_blocks(ciphertext), start=1):
        o = aes.encrypt_block(prev)
        p = xor_bytes(c, o)
        steps.append(BlockStep(i, c, prev, o, p, xor_with=o,
                               note="P_i = C_i ⊕ E_K(C_{i-1})"))
        padded += p
        prev = c
    return ModeResult("CFB", "decrypt", unpad(padded), padded, steps, iv=iv)


# --------------------------------------------------------------------------
# OFB - Output Feedback
#   O_i = E_K(O_{i-1}), O_0 = IV      C_i = P_i (+) O_i      P_i = C_i (+) O_i
#   The keystream O_i does not depend on the message.
# --------------------------------------------------------------------------
def _ofb(key: bytes, data: bytes, iv: bytes, decrypting: bool) -> List[BlockStep]:
    aes = AES128(key)
    steps, prev = [], iv
    for i, blk in enumerate(split_blocks(data), start=1):
        o = aes.encrypt_block(prev)
        out = xor_bytes(blk, o)
        note = "P_i = C_i ⊕ O_i,  O_i = E_K(O_{i-1})" if decrypting \
            else "C_i = P_i ⊕ O_i,  O_i = E_K(O_{i-1})"
        steps.append(BlockStep(i, blk, prev, o, out, xor_with=o, note=note))
        prev = o
    return steps


def ofb_encrypt(key: bytes, plaintext: bytes, iv: bytes = ZERO_IV) -> ModeResult:
    _check_key(key)
    _check_iv(iv)
    padded = pad(plaintext)
    steps = _ofb(key, padded, iv, decrypting=False)
    out = b"".join(s.block_out for s in steps)
    return ModeResult("OFB", "encrypt", out, padded, steps, iv=iv)


def ofb_decrypt(key: bytes, ciphertext: bytes, iv: bytes = ZERO_IV) -> ModeResult:
    _check_key(key)
    _check_iv(iv)
    _check_ciphertext(ciphertext)
    steps = _ofb(key, ciphertext, iv, decrypting=True)
    padded = b"".join(s.block_out for s in steps)
    return ModeResult("OFB", "decrypt", unpad(padded), padded, steps, iv=iv)


# --------------------------------------------------------------------------
# CTR - Counter
#   T_i = (initial counter + i - 1) mod 2^128
#   C_i = P_i (+) E_K(T_i)        P_i = C_i (+) E_K(T_i)
# --------------------------------------------------------------------------
def _ctr(key: bytes, data: bytes, initial: int, decrypting: bool) -> List[BlockStep]:
    aes = AES128(key)
    steps = []
    for i, blk in enumerate(split_blocks(data), start=1):
        t = counter_block(initial, i - 1)
        o = aes.encrypt_block(t)
        out = xor_bytes(blk, o)
        note = "P_i = C_i ⊕ E_K(T_i)" if decrypting else "C_i = P_i ⊕ E_K(T_i)"
        steps.append(BlockStep(i, blk, t, o, out, xor_with=o, note=note))
    return steps


def ctr_encrypt(key: bytes, plaintext: bytes, counter: Union[int, bytes, str]) -> ModeResult:
    _check_key(key)
    initial = counter_to_int(counter)
    padded = pad(plaintext)
    steps = _ctr(key, padded, initial, decrypting=False)
    out = b"".join(s.block_out for s in steps)
    return ModeResult("CTR", "encrypt", out, padded, steps, counter=initial)


def ctr_decrypt(key: bytes, ciphertext: bytes, counter: Union[int, bytes, str]) -> ModeResult:
    _check_key(key)
    _check_ciphertext(ciphertext)
    initial = counter_to_int(counter)
    steps = _ctr(key, ciphertext, initial, decrypting=True)
    padded = b"".join(s.block_out for s in steps)
    return ModeResult("CTR", "decrypt", unpad(padded), padded, steps, counter=initial)


# --------------------------------------------------------------------------
# One entry point for all modes (used by the CLI and the GUI)
# --------------------------------------------------------------------------
_ENCRYPT: Dict[str, Callable[..., ModeResult]] = {
    "ECB": ecb_encrypt, "CBC": cbc_encrypt, "CFB": cfb_encrypt,
    "OFB": ofb_encrypt, "CTR": ctr_encrypt,
}
_DECRYPT: Dict[str, Callable[..., ModeResult]] = {
    "ECB": ecb_decrypt, "CBC": cbc_decrypt, "CFB": cfb_decrypt,
    "OFB": ofb_decrypt, "CTR": ctr_decrypt,
}


def _dispatch(table, mode: str, key: bytes, data: bytes, counter) -> ModeResult:
    mode = mode.upper()
    if mode not in table:
        raise ValueError(f"Unknown mode '{mode}'. Choose one of {', '.join(MODE_NAMES)}.")
    if mode == "CTR":
        if counter is None:
            raise ValueError("CTR mode needs an initial counter value.")
        return table[mode](key, data, counter)
    return table[mode](key, data)          # ECB, or CBC/CFB/OFB with the zero IV


def encrypt(mode: str, key: bytes, plaintext: bytes, counter=None) -> ModeResult:
    """Encrypt with any mode. `counter` is required for CTR only."""
    return _dispatch(_ENCRYPT, mode, key, plaintext, counter)


def decrypt(mode: str, key: bytes, ciphertext: bytes, counter=None) -> ModeResult:
    """Decrypt with any mode. `counter` is required for CTR only."""
    return _dispatch(_DECRYPT, mode, key, ciphertext, counter)
