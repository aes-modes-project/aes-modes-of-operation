# The AES-128 core

File: [`aesmodes/aes_core.py`](../aesmodes/aes_core.py)

AES is a **block cipher**: it turns exactly 16 bytes of plaintext into 16 bytes of ciphertext under a
16-byte key. Everything else in this project (the five modes) is built on top of the two functions
`AES128.encrypt_block()` and `AES128.decrypt_block()`.

## 1. The state

The 16 input bytes are arranged in a 4×4 matrix, **column by column** (as in FIPS-197):

```
input:  b0 b1 b2 ... b15

state:  b0  b4  b8  b12
        b1  b5  b9  b13
        b2  b6  b10 b14
        b3  b7  b11 b15
```

In code: `state[row][col] = block[row + 4*col]`.

## 2. Arithmetic in GF(2⁸)

AES treats every byte as a polynomial over GF(2), reduced modulo

m(x) = x⁸ + x⁴ + x³ + x + 1  (`0x11B`)

- `xtime(a)` multiplies by x (0x02): shift left, and XOR with 0x11B if a bit falls off.
- `gmul(a, b)` multiplies any two bytes with shift-and-add.
- `ginv(a)` computes the multiplicative inverse as a²⁵⁴, because a²⁵⁵ = 1 for a ≠ 0.

## 3. The S-box (computed, not typed)

Instead of copying a 256-entry table, which is easy to mistype, the S-box is **generated from its
definition**:

1. take the multiplicative inverse in GF(2⁸) (0 maps to 0);
2. apply the affine transformation  b ⊕ rotl(b,1) ⊕ rotl(b,2) ⊕ rotl(b,3) ⊕ rotl(b,4) ⊕ 0x63.

The inverse S-box is built by reversing the table. The tests check known values (S[0x00]=0x63,
S[0x53]=0xED) and that the table is a permutation.

## 4. Key expansion

The 16-byte key becomes **44 words** w[0..43] (4 bytes each), one 4-word round key per round
(rounds 0–10):

```
w[0..3] = the key itself
for i = 4 .. 43:
    temp = w[i-1]
    if i % 4 == 0:
        temp = SubWord(RotWord(temp)) XOR Rcon[i/4]
    w[i] = w[i-4] XOR temp
```

- `RotWord`: [a0,a1,a2,a3] → [a1,a2,a3,a0]
- `SubWord`: apply the S-box to each byte
- `Rcon`: 01 02 04 08 10 20 40 80 1B 36 (powers of x in GF(2⁸))

## 5. The four round operations

| Operation | What it does | Inverse |
|---|---|---|
| **SubBytes** | replaces each byte using the S-box (non-linearity) | InvSubBytes (inverse S-box) |
| **ShiftRows** | rotates row *r* left by *r* positions (spreads bytes across columns) | InvShiftRows (rotate right) |
| **MixColumns** | multiplies each column by the matrix [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]] in GF(2⁸) | InvMixColumns, matrix [[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]] |
| **AddRoundKey** | XORs the state with the round key | itself (XOR is its own inverse) |

## 6. Encryption and decryption

```
Encrypt:                          Decrypt (inverse cipher):
  AddRoundKey(k0)                   AddRoundKey(k10)
  rounds 1..9:                      rounds 1..9:
    SubBytes                          InvShiftRows
    ShiftRows                         InvSubBytes
    MixColumns                        AddRoundKey(k[10-round])
    AddRoundKey(k_round)              InvMixColumns
  round 10 (no MixColumns):         round 10 (no InvMixColumns):
    SubBytes, ShiftRows,              InvShiftRows, InvSubBytes,
    AddRoundKey(k10)                  AddRoundKey(k0)
```

## 7. The trace (for the GUI)

Both functions accept an optional `trace` list. When given, every intermediate state is appended as

```python
{"round": 3, "step": "MixColumns", "state": [[...], [...], [...], [...]]}
```

An encryption produces 41 entries: Input, the initial AddRoundKey, 9 rounds × 4 steps and the final
round × 3 steps. The GUI uses this to display the cipher step by step.

## 8. Verification

| Test | Source | Expected |
|---|---|---|
| Key expansion | FIPS-197 A.1 | w[4] = a0fafe17, w[43] = b6630ca6 |
| Encryption | FIPS-197 App. B | 3925841d02dc09fbdc118597196a0b32 |
| Encrypt + decrypt | FIPS-197 C.1 | 69c4e0d86a7b0430d8cdb78070b4c55a |
| Random round trips | – | decrypt(encrypt(x)) = x |
| Reference library | pycryptodome | identical ciphertexts |
