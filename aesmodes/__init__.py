"""
aesmodes - AES-128 and its five modes of operation (ECB, CBC, CFB, OFB, CTR).

EECE 455/632 Cryptography and Network Security - Project 8.

Public API (grows as the project progresses):

    from aesmodes import AES128
    aes = AES128(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    ct = aes.encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff"))
"""

from .aes_core import AES128, format_state, key_expansion, state_to_hex
from .modes import BlockStep, ModeResult, ecb_decrypt, ecb_encrypt
from .padding import PaddingError, pad, unpad

__all__ = [
    "AES128", "key_expansion", "format_state", "state_to_hex",
    "pad", "unpad", "PaddingError",
    "ModeResult", "BlockStep", "ecb_encrypt", "ecb_decrypt",
]
__version__ = "0.2.0"
