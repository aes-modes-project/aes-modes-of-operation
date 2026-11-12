# Comparing the five modes

Summary for the report and presentation. Every row is backed by a test in
[`tests/test_modes.py`](../tests/test_modes.py) or [`tests/test_ecb.py`](../tests/test_ecb.py).

## Formulas

| Mode | Encryption | Decryption | Starting value |
|---|---|---|---|
| ECB | C_i = E_K(P_i) | P_i = D_K(C_i) | – |
| CBC | C_i = E_K(P_i ⊕ C_{i-1}) | P_i = D_K(C_i) ⊕ C_{i-1} | C_0 = IV = 0 |
| CFB | C_i = P_i ⊕ E_K(C_{i-1}) | P_i = C_i ⊕ E_K(C_{i-1}) | C_0 = IV = 0 |
| OFB | C_i = P_i ⊕ O_i, O_i = E_K(O_{i-1}) | P_i = C_i ⊕ O_i | O_0 = IV = 0 |
| CTR | C_i = P_i ⊕ E_K(T_i) | P_i = C_i ⊕ E_K(T_i) | T_1 = user's counter |

## Properties

| | ECB | CBC | CFB | OFB | CTR |
|---|---|---|---|---|---|
| Needs AES **decryption** | ✔ | ✔ | ✘ | ✘ | ✘ |
| Hides repeated blocks | ✘ | ✔ | ✔ | ✔ | ✔ |
| Parallel encryption | ✔ | ✘ | ✘ | ✘ | ✔ |
| Parallel decryption | ✔ | ✔ | ✔ | ✘ | ✔ |
| Keystream can be precomputed | – | – | ✘ | ✔ | ✔ |
| Random access to block i | ✔ | ✔ | ✔ | ✘ | ✔ |
| Blocks damaged by 1 flipped ciphertext bit | 1 (whole block) | 2 (whole block + 1 bit) | 2 (1 bit + whole block) | 1 bit only | 1 bit only |
| Behaves like a stream cipher | ✘ | ✘ | ✔ | ✔ | ✔ |

## Error propagation in detail

Flip **one bit** in ciphertext block C_1, then decrypt:

| Mode | P_1 | P_2 | P_3 … |
|---|---|---|---|
| ECB | garbled | ok | ok |
| CBC | garbled | **same bit flipped** | ok |
| CFB | **same bit flipped** | garbled | ok |
| OFB | **same bit flipped** | ok | ok |
| CTR | **same bit flipped** | ok | ok |

"Garbled" means about half the bits of that block change, because AES spreads one bit change across
the whole block (the avalanche effect).

## About the specification's choices

- **Zero IV.** It makes results reproducible and easy to check by hand, which suits an educational
  tool. In real use it's insecure: identical messages give identical ciphertexts in CBC/CFB, and in
  OFB every message under the same key reuses the same keystream.
- **Padding in every mode.** Only ECB and CBC strictly need it. CFB, OFB and CTR could stop at the
  message length, but padding everywhere keeps all five modes consistent with the specification.
- **User-chosen CTR counter.** This lets the user see that a different counter gives a completely
  different ciphertext, and that the receiver needs the same counter to decrypt.

## When each mode is used in practice

- **ECB**: only for single blocks (for example, wrapping one key); never for messages.
- **CBC**: historically the most common (older TLS, disk and file encryption), with random IVs.
- **CFB / OFB**: stream-like uses such as serial links and older protocols; OFB is popular where bit
  errors are common (satellite links), since errors don't spread.
- **CTR**: modern default, the basis of AES-GCM used in TLS 1.3, because it's fully parallel.
