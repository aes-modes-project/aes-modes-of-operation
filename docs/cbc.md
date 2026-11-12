# CBC: Cipher Block Chaining

File: [`aesmodes/modes.py`](../aesmodes/modes.py), functions `cbc_encrypt` and `cbc_decrypt`.

## Definition

```
C_0 = IV = 00000000000000000000000000000000     (project specification)

Encryption:  C_i = E_K(P_i ⊕ C_{i-1})
Decryption:  P_i = D_K(C_i) ⊕ C_{i-1}
```

Before encryption, each plaintext block is XORed with the **previous ciphertext block**. The first
block is XORed with the IV.

```
        P_1             P_2             P_3
         │               │               │
 IV ──► (⊕)      ┌────► (⊕)      ┌────► (⊕)
         │       │       │       │       │
      ┌──▼──┐    │    ┌──▼──┐    │    ┌──▼──┐
      │ E_K │    │    │ E_K │    │    │ E_K │
      └──┬──┘    │    └──┬──┘    │    └──┬──┘
         ├───────┘       ├───────┘       │
         ▼               ▼               ▼
        C_1             C_2             C_3
```

## Properties

| Property | CBC |
|---|---|
| IV needed | Yes (here, all zeros) |
| Uses AES decryption to decrypt | **Yes** |
| Parallel encryption / decryption | No / **Yes** (every C_{i-1} is already known) |
| Hides patterns | Yes, within a message: repeated plaintext blocks give different ciphertext blocks |
| Error propagation | A bit error in C_i garbles all of P_i and flips the **same bit** in P_{i+1}; later blocks are fine |

## Effect of the zero IV

With a fixed IV, encrypting the same message twice under the same key gives the **same ciphertext**,
so an observer can tell when a message repeats. Messages that share the same first blocks also share
the same first ciphertext blocks. Real systems use a fresh random IV for each message. This project
uses zeros because the specification requires it and because it makes results reproducible
(see `test_zero_iv_is_deterministic`).

## What the GUI shows per block

| Field | Encryption | Decryption |
|---|---|---|
| `block_in` | P_i | C_i |
| `xor_with` | C_{i-1} (the IV for i = 1) | C_{i-1} (the IV for i = 1) |
| `aes_input` | P_i ⊕ C_{i-1} | C_i |
| `aes_output` / `block_out` | C_i | D_K(C_i), then P_i after the XOR |

## Verification

- **NIST SP 800-38A F.2.1** (CBC-AES128), using the NIST IV `000102…0f`.
- Matches `pycryptodome` with the zero IV.
- Repeated plaintext blocks give different ciphertext blocks.
- Error propagation: one flipped ciphertext bit damages exactly 2 plaintext blocks.
