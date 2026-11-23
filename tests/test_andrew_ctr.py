"""Extra CTR tests contributed by Andrew; run at repository root: pytest -q tests/test_andrew_ctr.py"""
import pytest
from aesmodes import encrypt, decrypt

KEY = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
COUNTER = 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'

@pytest.mark.parametrize('data', [b'', b'a', b'hello', b'0123456789abcdef', b'x' * 31, b'x' * 32, bytes(range(100))])
def test_ctr_round_trip(data):
    ciphertext = encrypt('CTR', KEY, data, counter=COUNTER).output
    recovered = decrypt('CTR', KEY, ciphertext, counter=COUNTER).output
    assert recovered == data


def test_ctr_same_plaintext_different_counter_changes_ciphertext():
    data = b'Test message CTR'
    left = encrypt('CTR', KEY, data, counter='1').output
    right = encrypt('CTR', KEY, data, counter='2').output
    assert left != right


def test_ctr_is_deterministic_with_same_counter():
    data = b'Test message CTR'
    assert encrypt('CTR', KEY, data, counter='a').output == encrypt('CTR', KEY, data, counter='a').output
