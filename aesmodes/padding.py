"""
padding.py - padding of the last block, as required by the project spec:

    "padding of last block should be done with zeroes along with count of pad size"

Scheme (ANSI X.923 style):
    * append n bytes so the length becomes a multiple of 16 (1 <= n <= 16);
    * the first n-1 added bytes are 0x00;
    * the LAST added byte is n, the number of padding bytes.

If the message is already a multiple of 16 bytes, a FULL extra block
(00 00 ... 00 10) is added. Otherwise the receiver could not tell whether the
last byte of the message is data or padding.

Examples (16-byte blocks):
    "HELLO" (5 bytes)  -> 48 45 4c 4c 4f 00 00 00 00 00 00 00 00 00 00 0b
    15 bytes           -> <15 bytes> 01
    16 bytes           -> <16 bytes> 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10
"""

BLOCK_SIZE = 16


class PaddingError(ValueError):
    """Raised when padding is malformed (wrong key, corrupted data, ...)."""


def pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Pad `data` with zeros followed by a pad-count byte."""
    if not 1 <= block_size <= 255:
        raise ValueError("block_size must be between 1 and 255")
    n = block_size - (len(data) % block_size)        # always 1..block_size
    return bytes(data) + b"\x00" * (n - 1) + bytes([n])


def unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Remove padding added by `pad`, checking that it is well formed."""
    if len(data) == 0 or len(data) % block_size != 0:
        raise PaddingError(
            f"Padded data length must be a positive multiple of {block_size} bytes "
            f"(got {len(data)})."
        )
    n = data[-1]
    if not 1 <= n <= block_size:
        raise PaddingError(f"Invalid pad-count byte 0x{n:02x}.")
    if any(b != 0 for b in data[-n:-1]):
        raise PaddingError("Padding bytes before the count byte are not all zero.")
    return bytes(data[:-n])


def padding_bytes(data_len: int, block_size: int = BLOCK_SIZE) -> int:
    """How many padding bytes `pad` would add to a message of `data_len` bytes."""
    return block_size - (data_len % block_size)
