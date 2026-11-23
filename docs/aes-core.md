# The AES core (128-, 192- and 256-bit keys)

File: [`aesmodes/aes_core.py`](../aesmodes/aes_core.py)

AES is a **block cipher**: it turns exactly 16 bytes of plaintext into 16 bytes of ciphertext under a
16-byte key. Everything else in this project (the five modes) is built on top of the two functions
`AES.encrypt_block()` and `AES.decrypt_block()`.

The block is always 16 bytes. The **key length** selects the variant, and with it the number of rounds
and round keys:

| Variant | Key | N<sub>k</sub> (key words) | N<sub>r</sub> (rounds) | Words in key schedule | Steps in the trace |
|---|---|---|---|---|---|
| AES-128 | 16 bytes | 4 | 10 | 44 | 41 |
| AES-192 | 24 bytes | 6 | 12 | 52 | 49 |
| AES-256 | 32 bytes | 8 | 14 | 60 | 57 |

```python
from aesmodes import AES
aes = AES(key)          # key of 16, 24 or 32 bytes; aes.nr is 10, 12 or 14
```

`AES128` is kept as another name for the same class, so code from the earlier steps still works.

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

The key becomes **N<sub>b</sub>·(N<sub>r</sub>+1) words** (4 bytes each): 44 for AES-128, 52 for AES-192
and 60 for AES-256, giving one 4-word round key per round (rounds 0 to N<sub>r</sub>):

```
w[0 .. Nk-1] = the key itself
for i = Nk .. 4*(Nr+1) - 1:
    temp = w[i-1]
    if i % Nk == 0:
        temp = SubWord(RotWord(temp)) XOR Rcon[i/Nk]
    else if Nk == 8 and i % Nk == 4:          # AES-256 only
        temp = SubWord(temp)
    w[i] = w[i-Nk] XOR temp
```

Differences between the key sizes:

- **AES-128** (N<sub>k</sub> = 4): every round key starts with a "g" word (RotWord, SubWord, Rcon).
- **AES-192** (N<sub>k</sub> = 6): the g-step happens every 6 words, so it doesn't line up with the 4-word
  round keys. The key itself fills round key 0 and half of round key 1.
- **AES-256** (N<sub>k</sub> = 8): the key fills round keys 0 and 1. Every 8 words there's the g-step, plus
  an **extra SubWord** (without RotWord or Rcon) halfway through, at i mod 8 = 4.

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

An encryption produces 4·N<sub>r</sub> + 1 entries: Input, the initial AddRoundKey,
(N<sub>r</sub> − 1) rounds × 4 steps and the final round × 3 steps. That's 41 for AES-128, 49 for AES-192
and 57 for AES-256. The learning app uses this to display the cipher step by step.

## 8. Verification

| Test | Source | Expected |
|---|---|---|
| Key expansion, AES-128 | FIPS-197 A.1 | w[4] = a0fafe17, w[43] = b6630ca6 |
| Key expansion, AES-192 | FIPS-197 A.2 | w[6] = fe0c91f7, w[51] = 01002202 |
| Key expansion, AES-256 | FIPS-197 A.3 | w[8] = 9ba35411, w[12] = a8b09c1a (extra SubWord), w[59] = 706c631e |
| Encryption | FIPS-197 App. B | 3925841d02dc09fbdc118597196a0b32 |
| Encrypt + decrypt, AES-128 | FIPS-197 C.1 | 69c4e0d86a7b0430d8cdb78070b4c55a |
| Encrypt + decrypt, AES-192 | FIPS-197 C.2 | dda97ca4864cdfe06eaf70a0ec0d7191 |
| Encrypt + decrypt, AES-256 | FIPS-197 C.3 | 8ea2b7ca516745bfeafc49904b496089 |
| Random round trips | – | decrypt(encrypt(x)) = x |
| Reference library | pycryptodome | identical ciphertexts |
