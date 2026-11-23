from collections.abc import Iterator
from dataclasses import dataclass

from aesmodes.aes_core import AES128
from aesmodes.padding import BLOCK_SIZE, pad, unpad


BytesLike = bytes | bytearray | memoryview
ZERO_IV = bytes(BLOCK_SIZE)


@dataclass
class BlockStep:
    index: int
    block_in: bytes
    aes_input: bytes
    aes_output: bytes
    block_out: bytes
    note: str
    xor_with: bytes | None = None


@dataclass
class ModeResult:
    mode: str
    operation: str
    output: bytes
    padded: bytes
    steps: list[BlockStep]
    iv: bytes | None = None
    counter: None = None

    def hex(self) -> str:
        return self.output.hex()


def _blocks(data: bytes) -> Iterator[bytes]:
    for offset in range(0, len(data), BLOCK_SIZE):
        yield data[offset:offset + BLOCK_SIZE]


def _as_bytes(value: BytesLike, field: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ValueError(f"{field} must be bytes.")
    return bytes(value)


def _aes(key: BytesLike) -> AES128:
    key = _as_bytes(key, "Key")
    if len(key) != BLOCK_SIZE:
        raise ValueError("The AES-128 key must be exactly 16 bytes.")
    return AES128(key)


def _valid_ciphertext(ciphertext: BytesLike) -> bytes:
    ciphertext = _as_bytes(ciphertext, "Ciphertext")
    if not ciphertext or len(ciphertext) % BLOCK_SIZE:
        raise ValueError("Ciphertext must be a nonempty multiple of 16 bytes.")
    return ciphertext


def _check_strip_padding(strip_padding: bool) -> None:
    if not isinstance(strip_padding, bool):
        raise ValueError("strip_padding must be True or False.")


def _valid_iv(iv: BytesLike) -> bytes:
    iv = _as_bytes(iv, "CBC IV")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("The CBC IV must be exactly 16 bytes.")
    return iv


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def cbc_encrypt(key: BytesLike, plaintext: BytesLike, iv: BytesLike = ZERO_IV) -> ModeResult:
    iv = _valid_iv(iv)
    aes = _aes(key)
    padded = pad(_as_bytes(plaintext, "Plaintext"))
    previous_cipher = iv
    steps = []
    for index, plain in enumerate(_blocks(padded), start=1):
        mixed = _xor(plain, previous_cipher)
        cipher = aes.encrypt_block(mixed)
        steps.append(BlockStep(index, plain, mixed, cipher, cipher,
                               note="C_i = E_K(P_i ⊕ C_{i-1})", xor_with=previous_cipher))
        previous_cipher = cipher

    ciphertext = b"".join(step.block_out for step in steps)
    return ModeResult("CBC", "encrypt", ciphertext, padded, steps, iv=iv)


def cbc_decrypt(
    key: BytesLike, ciphertext: BytesLike, iv: BytesLike = ZERO_IV, strip_padding: bool = True
) -> ModeResult:
    iv = _valid_iv(iv)
    ciphertext = _valid_ciphertext(ciphertext)
    _check_strip_padding(strip_padding)
    aes = _aes(key)
    previous_cipher = iv
    steps = []
    for index, cipher in enumerate(_blocks(ciphertext), start=1):
        decrypted = aes.decrypt_block(cipher)
        plain = _xor(decrypted, previous_cipher)
        steps.append(BlockStep(index, cipher, cipher, decrypted, plain,
                               note="P_i = D_K(C_i) ⊕ C_{i-1}", xor_with=previous_cipher))
        previous_cipher = cipher

    padded = b"".join(step.block_out for step in steps)
    plaintext = unpad(padded) if strip_padding else padded
    return ModeResult("CBC", "decrypt", plaintext, padded, steps, iv=iv)
