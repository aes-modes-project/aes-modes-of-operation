"""
explain.py - turns the AES core and the modes into step-by-step data for the
learning app (aesmodes/web).

Nothing here re-implements AES: every value comes from the functions in
aes_core.py and modes.py. This module only records the intermediate values in
a JSON-friendly form (hex strings, 4x4 lists) and adds the extra detail the
visualizer needs (S-box lookups, MixColumns products, key-expansion steps).
"""

from typing import Dict, List, Optional

from . import aes_core as core
from .modes import (
    MODE_NAMES,
    ModeResult,
    counter_to_int,
    decrypt,
    encrypt,
    split_blocks,
)
from .padding import BLOCK_SIZE, padding_bytes

Matrix = List[List[str]]


# --------------------------------------------------------------------------
# Input parsing
# --------------------------------------------------------------------------
def parse_bytes(value: str, fmt: str, what: str = "Input") -> bytes:
    """Convert user input to bytes. fmt is 'text' (UTF-8) or 'hex'."""
    if fmt == "text":
        return value.encode("utf-8")
    if fmt == "hex":
        h = "".join(value.split())
        if h.lower().startswith("0x"):
            h = h[2:]
        if len(h) % 2:
            raise ValueError(f"{what}: hex must have an even number of digits.")
        try:
            return bytes.fromhex(h)
        except ValueError:
            raise ValueError(f"{what}: only hex digits 0-9 and a-f are allowed.") from None
    raise ValueError(f"Unknown format '{fmt}'.")


def parse_key(value: str) -> bytes:
    key = parse_bytes(value, "hex", "Key")
    if len(key) != 16:
        raise ValueError(f"Key must be exactly 32 hex digits (16 bytes); got {len(key) * 2}.")
    return key


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def hx(b: bytes) -> str:
    return bytes(b).hex()


def mat(s: core.State) -> Matrix:
    return [[f"{v:02x}" for v in row] for row in s]


def word_hex(w: List[int]) -> str:
    return bytes(w).hex()


# --------------------------------------------------------------------------
# Key expansion
# --------------------------------------------------------------------------
def key_expansion_details(key: bytes) -> List[Dict]:
    """The 44 words with how each one was computed."""
    w = core.key_expansion(key)
    out = []
    for i, word in enumerate(w):
        item = {"i": i, "word": word_hex(word), "round": i // 4}
        if i < 4:
            item["kind"] = "key"
        else:
            prev, back = w[i - 1], w[i - 4]
            item["prev"] = word_hex(prev)
            item["back"] = word_hex(back)
            if i % 4 == 0:
                rot = core.rot_word(prev)
                sub = core.sub_word(rot)
                rcon = [core.RCON[i // 4 - 1], 0, 0, 0]
                temp = [a ^ b for a, b in zip(sub, rcon)]
                item.update(kind="g", rot=word_hex(rot), sub=word_hex(sub),
                            rcon=word_hex(rcon), temp=word_hex(temp))
            else:
                item["kind"] = "xor"
        out.append(item)
    return out


# --------------------------------------------------------------------------
# AES walkthrough (encryption of one block)
# --------------------------------------------------------------------------
def _mix_detail(before: core.State, after: core.State) -> List[Dict]:
    """For each column: the input column, output column, and the four products per output byte."""
    cols = []
    for c in range(4):
        col = [before[r][c] for r in range(4)]
        rows = []
        for r in range(4):
            terms = []
            for k in range(4):
                coef = core._MIX[r][k]
                terms.append({"coef": coef, "byte": f"{col[k]:02x}",
                              "product": f"{core.gmul(coef, col[k]):02x}"})
            rows.append({"terms": terms, "result": f"{after[r][c]:02x}"})
        cols.append({"in": [f"{v:02x}" for v in col],
                     "out": [f"{after[r][c]:02x}" for r in range(4)], "rows": rows})
    return cols


def aes_walkthrough(key: bytes, block: bytes) -> Dict:
    """Encrypt one block and record every step with its before/after states."""
    if len(block) != 16:
        raise ValueError("AES works on exactly 16 bytes.")
    aes = core.AES128(key)
    rks = aes.round_keys
    steps: List[Dict] = []

    def add(rnd, op, before, after, **extra):
        steps.append({"round": rnd, "op": op, "before": mat(before), "after": mat(after), **extra})

    s = core.bytes_to_state(block)
    add(0, "Input", s, s)
    t = core.add_round_key(s, rks[0])
    add(0, "AddRoundKey", s, t, roundKey=mat(rks[0]))
    s = t
    for rnd in range(1, core.NR + 1):
        t = core.sub_bytes(s)
        add(rnd, "SubBytes", s, t)
        s = t
        t = core.shift_rows(s)
        add(rnd, "ShiftRows", s, t)
        s = t
        if rnd != core.NR:
            t = core.mix_columns(s)
            add(rnd, "MixColumns", s, t, mix=_mix_detail(s, t))
            s = t
        t = core.add_round_key(s, rks[rnd])
        add(rnd, "AddRoundKey", s, t, roundKey=mat(rks[rnd]))
        s = t

    ciphertext = core.state_to_bytes(s)
    assert ciphertext == aes.encrypt_block(block)          # same result as the core cipher
    return {
        "key": hx(key),
        "plaintext": hx(block),
        "ciphertext": ciphertext.hex(),
        "roundKeys": [mat(k) for k in rks],
        "keyExpansion": key_expansion_details(key),
        "steps": steps,
    }


def sbox_tables() -> Dict:
    return {"sbox": [f"{v:02x}" for v in core.SBOX],
            "invSbox": [f"{v:02x}" for v in core.INV_SBOX]}


# --------------------------------------------------------------------------
# Modes
# --------------------------------------------------------------------------
def _try_text(b: bytes) -> Optional[str]:
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return None


def mode_result_to_dict(res: ModeResult, message_len: Optional[int] = None) -> Dict:
    d = {
        "mode": res.mode,
        "operation": res.operation,
        "output": res.output.hex(),
        "outputText": _try_text(res.output) if res.operation == "decrypt" else None,
        "padded": res.padded.hex(),
        "iv": res.iv.hex() if res.iv is not None else None,
        "counter": f"{res.counter:032x}" if res.counter is not None else None,
        "steps": [
            {
                "index": s.index,
                "blockIn": hx(s.block_in),
                "aesInput": hx(s.aes_input),
                "aesOutput": hx(s.aes_output),
                "xorWith": hx(s.xor_with) if s.xor_with is not None else None,
                "blockOut": hx(s.block_out),
                "note": s.note,
            }
            for s in res.steps
        ],
    }
    if message_len is not None:
        d["messageLength"] = message_len
        d["padCount"] = padding_bytes(message_len)
    return d


def run_mode(mode: str, operation: str, key: bytes, data: bytes, counter=None) -> Dict:
    mode = mode.upper()
    if operation == "encrypt":
        res = encrypt(mode, key, data, counter=counter)
        return mode_result_to_dict(res, message_len=len(data))
    if operation == "decrypt":
        res = decrypt(mode, key, data, counter=counter)
        d = mode_result_to_dict(res)
        d["messageLength"] = len(res.output)
        d["padCount"] = len(res.padded) - len(res.output)
        return d
    raise ValueError("Operation must be 'encrypt' or 'decrypt'.")


# --------------------------------------------------------------------------
# Experiments
# --------------------------------------------------------------------------
def _bit_diff(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def bitflip_experiment(key: bytes, message: bytes, counter, byte_index: int, bit: int) -> Dict:
    """Flip one ciphertext bit in every mode and report how many plaintext bits change per block."""
    rows = []
    n_bytes = None
    for mode in MODE_NAMES:
        ct = bytearray(encrypt(mode, key, message, counter=counter).output)
        n_bytes = len(ct)
        if not 0 <= byte_index < len(ct):
            raise ValueError(f"Byte position must be between 0 and {len(ct) - 1}.")
        if not 0 <= bit <= 7:
            raise ValueError("Bit must be between 0 and 7.")
        ct[byte_index] ^= 1 << (7 - bit)
        damaged = decrypt(mode, key, bytes(ct), counter=counter, strip_padding=False).padded
        original = encrypt(mode, key, message, counter=counter).padded
        blocks = [
            {"bits": _bit_diff(o, d), "original": hx(o), "damaged": hx(d)}
            for o, d in zip(split_blocks(original), split_blocks(damaged))
        ]
        rows.append({"mode": mode, "blocks": blocks})
    return {"byte": byte_index, "bit": bit, "block": byte_index // BLOCK_SIZE,
            "ciphertextLength": n_bytes, "modes": rows}


def encrypt_image(mode: str, key: bytes, pixels: bytes, counter=None) -> bytes:
    """Encrypt raw pixel bytes and return exactly len(pixels) bytes (padding dropped) for display."""
    if len(pixels) > 200_000:
        raise ValueError("Image too large for the demo.")
    return encrypt(mode, key, pixels, counter=counter).output[:len(pixels)]


__all__ = [
    "parse_bytes", "parse_key", "aes_walkthrough", "key_expansion_details", "sbox_tables",
    "run_mode", "mode_result_to_dict", "bitflip_experiment", "encrypt_image",
    "counter_to_int",
]
