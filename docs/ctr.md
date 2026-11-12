# CTR: Counter mode

File: [`aesmodes/modes.py`](../aesmodes/modes.py), functions `ctr_encrypt` and `ctr_decrypt`.

## Definition

```
T_1 = initial counter (chosen by the user, 128 bits)
T_i = (T_1 + i − 1) mod 2^128

Encryption:  C_i = P_i ⊕ E_K(T_i)
Decryption:  P_i = C_i ⊕ E_K(T_i)
```

AES encrypts a sequence of **counter values**, producing a keystream that is XORed with the message.

```
     T_1             T_2 = T_1+1      T_3 = T_1+2
      │                │                │
   ┌──▼──┐          ┌──▼──┐          ┌──▼──┐
   │ E_K │          │ E_K │          │ E_K │
   └──┬──┘          └──┬──┘          └──┬──┘
P_1─►(⊕)        P_2─►(⊕)        P_3─►(⊕)
      ▼                ▼                ▼
     C_1              C_2              C_3
```

## The initial counter (user input)

As the specification requires, the user sets the initial counter. It can be given as:

| Form | Example | Meaning |
|---|---|---|
| hex string, up to 32 digits | `"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"`, `"1"`, `"0x2a"` | big-endian 128-bit value |
| integer | `5` | counter = 5 |
| 16 bytes | `bytes.fromhex("00…05")` | big-endian 128-bit value |

The counter increases by 1 per block and **wraps around** from `ff…ff` to `00…00` (mod 2¹²⁸). The
receiver must use the **same initial counter** to decrypt.

## Properties

| Property | CTR |
|---|---|
| IV needed | No, the initial counter plays that role |
| Uses AES decryption to decrypt | **No** |
| Parallel encryption / decryption | **Yes / Yes**: every block is independent |
| Random access | Yes: block i can be decrypted alone with E_K(T_i) |
| Hides patterns | Yes |
| Error propagation | **None**: a bit error in C_i flips only that bit of P_i |

## Danger of reusing a counter

As with OFB, encrypting two messages with the same key and the **same counter values** reuses the
keystream and leaks P ⊕ P'. In practice each message must use counter values that have never been
used before with that key.

## What the GUI shows per block

| Field | Meaning |
|---|---|
| `aes_input` | T_i, the counter block |
| `aes_output` = `xor_with` | E_K(T_i), the keystream block |
| `block_in` → `block_out` | P_i → C_i or C_i → P_i |

## Verification

- **NIST SP 800-38A F.5.1** (CTR-AES128, initial counter `f0f1…feff`).
- Matches `pycryptodome` for random initial counters.
- The counter increments per block and wraps at 2¹²⁸; invalid counters are rejected.
- Error propagation: one flipped ciphertext bit changes exactly one plaintext bit.
