"""
aesmodes - AES (128/192/256-bit keys) and its five modes of operation
(ECB, CBC, CFB, OFB, CTR).

EECE 455/632 Cryptography and Network Security - Project 8.

Quick start:

    from aesmodes import encrypt, decrypt
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    res = encrypt("CBC", key, b"Hello")                  # zero IV, zero+count padding
    res = encrypt("CTR", key, b"Hello", counter="01")    # CTR needs an initial counter
    decrypt("CTR", key, res.output, counter="01").output # b"Hello"
"""

from .aes_core import AES, AES128, KEY_SIZES, format_state, key_expansion, state_to_hex
from .modes import (
    MODE_NAMES,
    ZERO_IV,
    BlockStep,
    ModeResult,
    cbc_decrypt,
    cbc_encrypt,
    cfb_decrypt,
    cfb_encrypt,
    counter_to_int,
    ctr_decrypt,
    ctr_encrypt,
    decrypt,
    ecb_decrypt,
    ecb_encrypt,
    encrypt,
    ofb_decrypt,
    ofb_encrypt,
)
from .padding import PaddingError, pad, unpad

__all__ = [
    "AES", "AES128", "KEY_SIZES", "key_expansion", "format_state", "state_to_hex",
    "pad", "unpad", "PaddingError",
    "MODE_NAMES", "ZERO_IV", "ModeResult", "BlockStep", "counter_to_int",
    "encrypt", "decrypt",
    "ecb_encrypt", "ecb_decrypt", "cbc_encrypt", "cbc_decrypt",
    "cfb_encrypt", "cfb_decrypt", "ofb_encrypt", "ofb_decrypt",
    "ctr_encrypt", "ctr_decrypt",
]
__version__ = "0.6.0"
