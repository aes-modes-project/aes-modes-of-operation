"""
modes.py - AES-128 modes of operation.

Implemented so far:  ECB
Coming next:         CBC, CFB, OFB, CTR

Every function returns a `ModeResult` containing the output bytes and one
`BlockStep` per block. A BlockStep records exactly what happened to that block
(what went into AES, what came out, what was XORed), so the GUI can display the
mode step by step.

Conventions (from the project specification):
    * key: 16 bytes (AES-128)
    * padding: zeros + pad-count byte (see padding.py)
    * IV: 16 zero bytes for CBC / CFB / OFB
    * CTR: initial counter chosen by the user
"""

from dataclasses import dataclass, field
from typing import List, Optional

from .aes_core import AES128
from .padding import BLOCK_SIZE, pad, unpad

ZERO_IV = bytes(BLOCK_SIZE)


# --------------------------------------------------------------------------
# Result types
# --------------------------------------------------------------------------
@dataclass
class BlockStep:
    """What happened to one block."""
    index: int                       # block number, starting at 1
    block_in: bytes                  # plaintext block (encrypt) / ciphertext block (decrypt)
    aes_input: bytes                 # what was fed into AES
    aes_output: bytes                # what AES produced
    block_out: bytes                 # resulting ciphertext / plaintext block
    xor_with: Optional[bytes] = None # value XORed in this step (None for ECB)
    note: str = ""                   # short human-readable description


@dataclass
class ModeResult:
    mode: str                        # "ECB", "CBC", ...
    operation: str                   # "encrypt" or "decrypt"
    output: bytes                    # final ciphertext, or plaintext with padding removed
    padded: bytes                    # padded plaintext (encrypt) / decrypted text before unpadding
    steps: List[BlockStep] = field(default_factory=list)

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


def _check_ciphertext(ct: bytes) -> None:
    if len(ct) == 0 or len(ct) % BLOCK_SIZE != 0:
        raise ValueError(
            f"Ciphertext length must be a positive multiple of {BLOCK_SIZE} bytes "
            f"(got {len(ct)})."
        )


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
