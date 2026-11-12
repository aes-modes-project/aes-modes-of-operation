# OFB: Output Feedback

File: [`aesmodes/modes.py`](../aesmodes/modes.py), functions `ofb_encrypt` and `ofb_decrypt`.

## Definition

```
O_0 = IV = 00000000000000000000000000000000
O_i = E_K(O_{i-1})                    (the keystream)

Encryption:  C_i = P_i ⊕ O_i
Decryption:  P_i = C_i ⊕ O_i
```

AES repeatedly encrypts its **own previous output**. This produces a keystream O_1, O_2, … that
**does not depend on the message at all**, and the message is XORed with it.

```
  IV ──► E_K ──► O_1 ──► E_K ──► O_2 ──► E_K ──► O_3
                  │               │               │
         P_1 ──► (⊕)     P_2 ──► (⊕)     P_3 ──► (⊕)
                  ▼               ▼               ▼
                 C_1             C_2             C_3
```

Encryption and decryption are **the same operation**: XOR with the same keystream.

## Properties

| Property | OFB |
|---|---|
| IV needed | Yes (here, all zeros) |
| Uses AES decryption to decrypt | **No** |
| Parallel encryption / decryption | No / No (but the keystream can be **precomputed** before the message arrives) |
| Hides patterns | Yes |
| Error propagation | **None**: a bit error in C_i flips only that one bit of P_i |

## Danger of reusing the IV

Because the keystream depends only on the key and the IV, two messages encrypted with the **same key
and same IV use the same keystream**. Then C ⊕ C' = P ⊕ P', which leaks information about both
messages. With the zero IV from the specification, this happens to every message under the same key.
That's acceptable for an educational tool, but it would be a serious flaw in practice.

## What the GUI shows per block

| Field | Meaning |
|---|---|
| `aes_input` | O_{i-1} (the IV for i = 1) |
| `aes_output` = `xor_with` | O_i, the keystream block |
| `block_in` → `block_out` | P_i → C_i or C_i → P_i |

## Verification

- **NIST SP 800-38A F.4.1** (OFB-AES128).
- Matches `pycryptodome` with the zero IV.
- Error propagation: one flipped ciphertext bit changes exactly one plaintext bit.
