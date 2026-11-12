"""Tests for aesmodes/padding.py (zeros + pad-count byte)."""

import pytest

from aesmodes.padding import PaddingError, pad, padding_bytes, unpad


def test_hello_example():
    assert pad(b"HELLO").hex() == "48454c4c4f" + "00" * 10 + "0b"


@pytest.mark.parametrize("length", [0, 1, 5, 15, 16, 17, 31, 32, 33, 100])
def test_padded_length_and_round_trip(length):
    data = bytes(range(length % 256)) * (length // 256 + 1)
    data = data[:length]
    padded = pad(data)
    assert len(padded) % 16 == 0
    assert len(padded) > len(data)                 # always adds at least 1 byte
    assert padded[-1] == padding_bytes(length)
    assert unpad(padded) == data


def test_one_byte_of_padding_is_just_the_count():
    assert pad(b"A" * 15)[-1:] == b"\x01"


def test_full_block_added_when_aligned():
    assert pad(b"A" * 16)[16:] == b"\x00" * 15 + b"\x10"


def test_empty_message_is_one_full_padding_block():
    assert pad(b"") == b"\x00" * 15 + b"\x10"


@pytest.mark.parametrize(
    "bad",
    [
        b"",                                  # empty
        b"\x00" * 15,                         # not a multiple of 16
        b"\x00" * 16,                         # count byte 0
        b"\x00" * 15 + b"\x11",               # count byte > 16
        b"\x00" * 13 + b"\x07\x00\x03",       # non-zero byte inside the padding
    ],
)
def test_malformed_padding_rejected(bad):
    with pytest.raises(PaddingError):
        unpad(bad)
