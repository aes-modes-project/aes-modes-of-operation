"""
filecrypt.py - a practical file and message encryptor built on the project's
own AES (aes_core.py) and its five modes of operation.

It is the engine behind the "AES Encryptor" website (encryptor/) and can also
be used from the command line:

    python -m aesmodes.filecrypt encrypt report.pdf --mode CBC --bits 256
    python -m aesmodes.filecrypt decrypt report.pdf.aesm

What it adds on top of modes.py
-------------------------------
* Streaming: data is processed block by block with the chaining state kept in a
  small object, so large files can be encrypted with progress updates and
  without storing a record of every block (modes.py keeps those for teaching).
* Speed: blocks go through fastaes.FastAES, a lookup-table version of our AES
  that gives identical results to aes_core.AES (checked by the tests).
* Keys from passwords: PBKDF2-HMAC-SHA256 with a random salt turns a password
  into an AES-128/192/256 key. A raw hex key can be used instead.
* Integrity: HMAC-SHA256 over the whole file (encrypt-then-MAC). The five modes
  on their own do not detect a wrong key or a modified ciphertext; the MAC does.
* A self-describing container (.aesm): the header records the mode, key size,
  IV or counter, salt and file name, so decryption only needs the password.

Everything uses the Python standard library (hashlib, hmac, os, struct), so the
same file runs in the browser with Pyodide.

Container layout (all integers big-endian)
------------------------------------------
    offset  size  field
    0       4     magic  b"AESM"
    4       1     version (1)
    5       1     mode: 0 ECB, 1 CBC, 2 CFB, 3 OFB, 4 CTR
    6       1     key length in bytes (16, 24, 32)
    7       1     key source: 0 raw hex key, 1 password (PBKDF2)
    8       1     flags: bit 0 = the IV/counter was chosen by the user or is zero
    9       4     PBKDF2 iterations (0 for a raw key)
    13      16    salt (zeros for a raw key)
    29      16    IV (CBC/CFB/OFB) or initial counter (CTR); zeros for ECB
    45      2     length of the original file name in bytes (n)
    47      n     original file name, UTF-8 (empty for text messages)
    47+n    ...   ciphertext (padded: zeros + pad-count byte, as in padding.py)
    end-32  32    HMAC-SHA256 of everything before it
"""

import argparse
import hashlib
import hmac
import os
import struct
import sys
from typing import Callable, Optional, Union

from .aes_core import KEY_SIZES
from .fastaes import FastAES
from .modes import MODE_NAMES, ZERO_IV, counter_to_int
from .padding import BLOCK_SIZE, PaddingError, pad, unpad

MAGIC = b"AESM"
VERSION = 1
HEADER_FIXED = 47
MAC_SIZE = 32
DEFAULT_ITERATIONS = 200_000
MAX_NAME = 255

Progress = Optional[Callable[[int, int], None]]   # progress(done_bytes, total_bytes)


class IntegrityError(ValueError):
    """Raised when the HMAC does not match: wrong password/key, or the data was changed."""


# --------------------------------------------------------------------------
# Streaming modes
# --------------------------------------------------------------------------
def _xor16(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(BLOCK_SIZE, "big")


class ModeStream:
    """
    Encrypts or decrypts a sequence of whole 16-byte blocks in one of the five
    modes, keeping the chaining value between calls to `process`.

    Gives exactly the same result as the functions in modes.py
    (tests/test_filecrypt.py checks this for every mode and key size).
    """

    def __init__(self, mode: str, key: bytes, decrypt: bool = False,
                 iv: bytes = ZERO_IV, counter: Union[int, bytes, str, None] = None):
        self.mode = mode.upper()
        if self.mode not in MODE_NAMES:
            raise ValueError(f"Unknown mode '{mode}'. Choose one of {', '.join(MODE_NAMES)}.")
        if len(iv) != BLOCK_SIZE:
            raise ValueError("IV must be exactly 16 bytes.")
        self.aes = FastAES(key)                     # same results as aes_core.AES, ~7x faster
        self.decrypt = decrypt
        self.prev = bytes(iv)                       # C_{i-1} (CBC, CFB) or O_{i-1} (OFB)
        if self.mode == "CTR":
            if counter is None:
                raise ValueError("CTR mode needs an initial counter.")
            self.ctr = counter_to_int(counter)

    def process(self, data: bytes) -> bytes:
        if len(data) % BLOCK_SIZE:
            raise ValueError("ModeStream.process needs whole 16-byte blocks.")
        enc, dec = self.aes.encrypt_block, self.aes.decrypt_block
        out = bytearray()
        for i in range(0, len(data), BLOCK_SIZE):
            blk = data[i:i + BLOCK_SIZE]
            m = self.mode
            if m == "ECB":
                o = dec(blk) if self.decrypt else enc(blk)
            elif m == "CBC":
                if self.decrypt:
                    o = _xor16(dec(blk), self.prev)
                    self.prev = blk
                else:
                    o = enc(_xor16(blk, self.prev))
                    self.prev = o
            elif m == "CFB":
                o = _xor16(blk, enc(self.prev))
                self.prev = blk if self.decrypt else o
            elif m == "OFB":
                self.prev = enc(self.prev)
                o = _xor16(blk, self.prev)
            else:  # CTR
                o = _xor16(blk, enc(self.ctr.to_bytes(BLOCK_SIZE, "big")))
                self.ctr = (self.ctr + 1) % (1 << 128)
            out += o
        return bytes(out)


def stream_apply(stream: ModeStream, data: bytes, progress: Progress = None,
                 chunk_blocks: int = 2048) -> bytes:
    """Run `stream` over `data` in chunks, reporting progress after each chunk."""
    out = bytearray()
    step = chunk_blocks * BLOCK_SIZE
    for i in range(0, len(data), step):
        out += stream.process(data[i:i + step])
        if progress:
            progress(min(i + step, len(data)), len(data))
    if progress and not data:
        progress(0, 0)
    return bytes(out)


# --------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------
def pbkdf2_sha256(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    """PBKDF2-HMAC-SHA256 (RFC 8018) written with hmac only.

    The browser's Python (Pyodide) has no hashlib.pbkdf2_hmac, so this gives
    the same bytes there. Normal Python uses the faster built-in version.
    """
    if hasattr(hashlib, "pbkdf2_hmac"):
        return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=dklen)
    base = hmac.new(password, digestmod=hashlib.sha256)
    out = b""
    block = 1
    while len(out) < dklen:
        h = base.copy()
        h.update(salt + struct.pack(">I", block))
        u = h.digest()
        acc = int.from_bytes(u, "big")
        for _ in range(iterations - 1):
            h = base.copy()
            h.update(u)
            u = h.digest()
            acc ^= int.from_bytes(u, "big")
        out += acc.to_bytes(32, "big")
        block += 1
    return out[:dklen]


def derive_keys(password: str, salt: bytes, key_len: int, iterations: int):
    """PBKDF2-HMAC-SHA256 -> (AES key, MAC key)."""
    if not password:
        raise ValueError("Enter a password.")
    material = pbkdf2_sha256(password.encode("utf-8"), salt, iterations, key_len + 32)
    return material[:key_len], material[key_len:]


def mac_key_for_raw(key: bytes) -> bytes:
    """MAC key for a raw hex key (kept separate from the AES key)."""
    return hashlib.sha256(b"aesm-mac-key" + key).digest()


def parse_hex_key(hex_key: str) -> bytes:
    h = "".join(hex_key.split()).lower().removeprefix("0x")
    try:
        key = bytes.fromhex(h)
    except ValueError:
        raise ValueError("The key must be written in hex (0-9, a-f).") from None
    if len(key) not in KEY_SIZES:
        raise ValueError("A hex key must have 32, 48 or 64 digits (AES-128, AES-192 or AES-256).")
    return key


# --------------------------------------------------------------------------
# Container
# --------------------------------------------------------------------------
def encrypt_container(data: bytes, *, mode: str = "CBC", password: Optional[str] = None,
                      hex_key: Optional[str] = None, key_bits: int = 256,
                      iv: Optional[bytes] = None, counter: Union[int, str, bytes, None] = None,
                      random_iv: bool = False, name: str = "",
                      iterations: int = DEFAULT_ITERATIONS, progress: Progress = None) -> bytes:
    """
    Encrypt `data` into a .aesm container.

    Give either a password (with key_bits 128/192/256) or a hex key (its length
    sets the key size). The IV is zero by default, as in the project
    specification; pass random_iv=True for a fresh random IV (or counter), or
    give your own `iv` / `counter`.
    """
    mode = mode.upper()
    if mode not in MODE_NAMES:
        raise ValueError(f"Unknown mode '{mode}'.")
    if (password is None) == (hex_key is None):
        raise ValueError("Give either a password or a hex key.")

    if hex_key is not None:
        key = parse_hex_key(hex_key)
        mac_key, source, iters, salt = mac_key_for_raw(key), 0, 0, bytes(16)
    else:
        if key_bits not in (128, 192, 256):
            raise ValueError("Key size must be 128, 192 or 256 bits.")
        salt = os.urandom(16)
        key, mac_key = derive_keys(password, salt, key_bits // 8, iterations)
        source, iters = 1, iterations

    user_chosen = 1
    if mode == "CTR":
        if random_iv or counter is None:
            start = int.from_bytes(os.urandom(16), "big") if random_iv else 0
            user_chosen = 0 if random_iv else 1
        else:
            start = counter_to_int(counter)
        ivfield = start.to_bytes(16, "big")
        stream = ModeStream(mode, key, counter=start)
    elif mode == "ECB":
        ivfield = bytes(16)
        stream = ModeStream(mode, key)
    else:
        if random_iv:
            ivfield, user_chosen = os.urandom(16), 0
        else:
            ivfield = bytes(iv) if iv is not None else ZERO_IV
            if len(ivfield) != 16:
                raise ValueError("IV must be 16 bytes.")
        stream = ModeStream(mode, key, iv=ivfield)

    name_b = name.encode("utf-8")[:MAX_NAME]
    header = (MAGIC + bytes([VERSION, MODE_NAMES.index(mode), len(key), source, user_chosen])
              + struct.pack(">I", iters) + salt + ivfield + struct.pack(">H", len(name_b)) + name_b)
    body = stream_apply(stream, pad(data), progress)
    tag = hmac.new(mac_key, header + body, hashlib.sha256).digest()
    return header + body + tag


def read_header(blob: bytes) -> dict:
    """Parse the header of a .aesm container (no key needed)."""
    if len(blob) < HEADER_FIXED + MAC_SIZE or blob[:4] != MAGIC:
        raise ValueError("This is not an AES Encryptor file (.aesm).")
    if blob[4] != VERSION:
        raise ValueError(f"Unsupported file version {blob[4]}.")
    mode_id, key_len, source, flags = blob[5], blob[6], blob[7], blob[8]
    if mode_id >= len(MODE_NAMES) or key_len not in KEY_SIZES or source not in (0, 1):
        raise ValueError("The file header is damaged.")
    (iters,) = struct.unpack(">I", blob[9:13])
    (name_len,) = struct.unpack(">H", blob[45:47])
    start = HEADER_FIXED + name_len
    if len(blob) < start + MAC_SIZE or (len(blob) - start - MAC_SIZE) % BLOCK_SIZE:
        raise ValueError("The file is truncated or damaged.")
    return {
        "mode": MODE_NAMES[mode_id], "keyBits": key_len * 8,
        "keySource": "password" if source == 1 else "hex key",
        "userChosenIV": bool(flags & 1), "iterations": iters,
        "salt": blob[13:29], "iv": blob[29:45],
        "name": blob[47:start].decode("utf-8", errors="replace"),
        "bodyStart": start, "ciphertextBytes": len(blob) - start - MAC_SIZE,
    }


def decrypt_container(blob: bytes, *, password: Optional[str] = None,
                      hex_key: Optional[str] = None, progress: Progress = None):
    """Check and decrypt a .aesm container. Returns (plaintext, header info)."""
    info = read_header(blob)
    if info["keySource"] == "password":
        if password is None:
            raise ValueError("This file was encrypted with a password.")
        key, mac_key = derive_keys(password, info["salt"], info["keyBits"] // 8, info["iterations"])
    else:
        if hex_key is None:
            raise ValueError("This file was encrypted with a hex key.")
        key = parse_hex_key(hex_key)
        if len(key) * 8 != info["keyBits"]:
            raise IntegrityError(f"This file needs a {info['keyBits']}-bit key.")
        mac_key = mac_key_for_raw(key)

    body_start, tag = info["bodyStart"], blob[-MAC_SIZE:]
    expected = hmac.new(mac_key, blob[:-MAC_SIZE], hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise IntegrityError("Wrong password or key, or the file has been changed.")

    mode = info["mode"]
    if mode == "CTR":
        stream = ModeStream(mode, key, decrypt=True, counter=info["iv"])
    else:
        stream = ModeStream(mode, key, decrypt=True, iv=info["iv"])
    padded = stream_apply(stream, blob[body_start:-MAC_SIZE], progress)
    try:
        plain = unpad(padded)
    except PaddingError as err:                       # cannot happen once the MAC matched
        raise IntegrityError(f"Invalid padding after decryption ({err}).") from None
    return plain, info


# --------------------------------------------------------------------------
# Text messages: the container in base64 with a short prefix
# --------------------------------------------------------------------------
TEXT_PREFIX = "AESM1:"


def encrypt_text(message: str, **kw) -> str:
    import base64
    return TEXT_PREFIX + base64.b64encode(encrypt_container(message.encode("utf-8"), **kw)).decode()


def decrypt_text(token: str, **kw):
    import base64
    t = "".join(token.split())
    if not t.startswith(TEXT_PREFIX):
        raise ValueError(f"An encrypted message starts with {TEXT_PREFIX}")
    try:
        blob = base64.b64decode(t[len(TEXT_PREFIX):], validate=True)
    except ValueError:
        raise ValueError("The encrypted message is not valid (base64 error).") from None
    plain, info = decrypt_container(blob, **kw)
    return plain.decode("utf-8", errors="replace"), info


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------
def _main(argv=None) -> None:
    import getpass                       # only the command line needs it (not the browser)
    ap = argparse.ArgumentParser(prog="python -m aesmodes.filecrypt",
                                 description="Encrypt or decrypt files with the project's own AES.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("encrypt", help="encrypt a file into FILE.aesm")
    e.add_argument("file")
    e.add_argument("--mode", default="CBC", choices=MODE_NAMES)
    e.add_argument("--bits", type=int, default=256, choices=(128, 192, 256))
    e.add_argument("--key", help="hex key instead of a password (32/48/64 digits)")
    e.add_argument("--random-iv", action="store_true", help="random IV/counter instead of zeros")
    e.add_argument("--counter", help="initial CTR counter in hex (default 0)")
    e.add_argument("-o", "--output")
    d = sub.add_parser("decrypt", help="decrypt a .aesm file")
    d.add_argument("file")
    d.add_argument("--key", help="hex key, if the file was encrypted with one")
    d.add_argument("-o", "--output")
    a = ap.parse_args(argv)

    try:
        with open(a.file, "rb") as f:
            data = f.read()
        if a.cmd == "encrypt":
            pw = None if a.key else getpass.getpass("Password: ")
            if pw is not None and pw != getpass.getpass("Repeat password: "):
                ap.error("The passwords do not match.")
            blob = encrypt_container(data, mode=a.mode, password=pw, hex_key=a.key, key_bits=a.bits,
                                     random_iv=a.random_iv, counter=a.counter,
                                     name=os.path.basename(a.file))
            out = a.output or a.file + ".aesm"
            with open(out, "wb") as f:
                f.write(blob)
            bits = len(parse_hex_key(a.key)) * 8 if a.key else a.bits
            print(f"Encrypted {len(data)} bytes with AES-{bits}-{a.mode} -> {out}")
        else:
            info = read_header(data)
            pw = None if info["keySource"] == "hex key" else getpass.getpass("Password: ")
            plain, info = decrypt_container(data, password=pw, hex_key=a.key)
            out = a.output or (info["name"] or os.path.splitext(a.file)[0] + ".dec")
            if os.path.exists(out) and not a.output:
                out = "decrypted-" + os.path.basename(out)
            with open(out, "wb") as f:
                f.write(plain)
            print(f"Decrypted AES-{info['keyBits']}-{info['mode']} file -> {out} (integrity check passed)")
    except (ValueError, OSError) as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    _main()
