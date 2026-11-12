# CFB: Cipher Feedback

File: [`aesmodes/modes.py`](../aesmodes/modes.py), functions `cfb_encrypt` and `cfb_decrypt`.

This project implements **full-block CFB (s = 128 bits)**, also called CFB-128: the feedback unit is a
whole 16-byte block.

## Definition

```
C_0 = IV = 00000000000000000000000000000000

Encryption:  C_i = P_i ⊕ E_K(C_{i-1})
Decryption:  P_i = C_i ⊕ E_K(C_{i-1})
```

AES encrypts the **previous ciphertext block**, and the result is XORed with the data. This turns the
block cipher into a **self-synchronizing stream cipher**.

```
  IV ──────┐      ┌─────────────┐      ┌─────────────┐
        ┌──▼──┐   │          ┌──▼──┐   │          ┌──▼──┐
        │ E_K │   │          │ E_K │   │          │ E_K │
        └──┬──┘   │          └──┬──┘   │          └──┬──┘
  P_1 ──► (⊕)     │   P_2 ──► (⊕)     │   P_3 ──► (⊕)
           ├──────┘             ├──────┘             │
           ▼                    ▼                    ▼
          C_1                  C_2                  C_3
```

## Key observation: no AES decryption

Both directions compute `E_K(C_{i-1})`, so **decryption uses AES *encryption***. The inverse cipher
(InvSubBytes, InvShiftRows, InvMixColumns) is never needed. The same holds for OFB and CTR.

## Properties

| Property | CFB |
|---|---|
| IV needed | Yes (here, all zeros) |
| Uses AES decryption to decrypt | **No** |
| Parallel encryption / decryption | No / **Yes** |
| Hides patterns | Yes |
| Error propagation | A bit error in C_i flips the **same bit** in P_i and garbles all of P_{i+1}; then it recovers (self-synchronizing) |

## Padding

CFB could encrypt a partial last block without padding (just use part of the keystream). To follow
the project specification consistently, the message is padded in all modes.

## What the GUI shows per block

| Field | Meaning |
|---|---|
| `aes_input` | C_{i-1} (the IV for i = 1) |
| `aes_output` = `xor_with` | E_K(C_{i-1}) |
| `block_in` → `block_out` | P_i → C_i (encryption) or C_i → P_i (decryption) |

## Verification

- **NIST SP 800-38A F.3.13** (CFB128-AES128).
- Matches `pycryptodome` (`segment_size=128`) with the zero IV.
- Error propagation: one flipped ciphertext bit damages exactly 2 plaintext blocks.
