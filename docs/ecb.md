# ECB: Electronic Codebook

File: [`aesmodes/modes.py`](../aesmodes/modes.py), functions `ecb_encrypt` and `ecb_decrypt`.

## Definition

```
Encryption:  C_i = E_K(P_i)
Decryption:  P_i = D_K(C_i)
```

The padded message is cut into 16-byte blocks, and **each block is encrypted on its own** with the same
key. ECB has no IV and no chaining.

```
   P_1        P_2        P_3
    │          │          │
 ┌──▼──┐    ┌──▼──┐    ┌──▼──┐
 │ E_K │    │ E_K │    │ E_K │
 └──┬──┘    └──┬──┘    └──┬──┘
    ▼          ▼          ▼
   C_1        C_2        C_3
```

## Properties

| Property | ECB |
|---|---|
| IV needed | No |
| Uses AES decryption to decrypt | **Yes** |
| Parallel encryption / decryption | Yes / Yes |
| Hides patterns | **No**: equal plaintext blocks give equal ciphertext blocks |
| Error propagation | A bit error in C_i corrupts only P_i (the whole block, about 50% of its bits) |

## The ECB weakness

Because the same input block always gives the same output block, **patterns in the plaintext are
visible in the ciphertext**. The test `test_identical_blocks_give_identical_ciphertext` demonstrates
this: encrypting `"YELLOW SUBMARINE"` three times gives three identical ciphertext blocks. This is why
ECB should only be used for single blocks (for example, encrypting a key) and why the chained modes
exist.

## Implementation

1. Pad the plaintext (zeros + count byte).
2. For each block, `C_i = aes.encrypt_block(P_i)`, recording a `BlockStep`.
3. To decrypt, run `aes.decrypt_block` on each block, then `unpad`.

## Verification

- **NIST SP 800-38A F.1.1** (ECB-AES128): the 4 reference blocks match exactly.
- Round trips for message lengths 0, 1, 15, 16, 17, 33 and 100 bytes.
- Cross-check against `pycryptodome` (padding applied first).
