# Padding

File: [`aesmodes/padding.py`](../aesmodes/padding.py)

AES works on whole 16-byte blocks, but messages can be any length, so the last block has to be
filled up. The project specification says:

> *padding of last block should be done with zeroes along with count of pad size*

## The scheme

To pad a message:

1. Compute **n = 16 − (length mod 16)**. This is always between 1 and 16.
2. Append **n − 1 zero bytes**.
3. Append **one byte holding n**.

This is the **ANSI X.923** padding scheme.

| Message length | Bytes added | Last block ends with |
|---|---|---|
| 5 (`HELLO`) | 11 | `… 00 00 00 00 00 00 00 00 00 00 0b` |
| 15 | 1 | `… 01` |
| 16 | **16 (a whole new block)** | `00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10` |
| 0 (empty) | 16 | `00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10` |

### Worked example

```
"HELLO" = 48 45 4C 4C 4F                                  (5 bytes, needs 11 more)
padded  = 48 45 4C 4C 4F 00 00 00 00 00 00 00 00 00 00 0B
                         └──── 10 zero bytes ───────┘ └ count = 11
```

### Why a full block is added when the length is already a multiple of 16

When decrypting, the receiver *always* reads the last byte as the pad count. If no padding were added
to a 16-byte message ending in, say, `…02`, the receiver would wrongly delete 2 bytes of real data.
Adding a full padding block makes removal unambiguous.

## Removing the padding

`unpad()` reads the last byte *n* and removes *n* bytes. It first checks that:

- the length is a positive multiple of 16;
- 1 ≤ n ≤ 16;
- the n − 1 bytes before the count byte are all zero.

If a check fails, it raises `PaddingError`. In practice this usually means a **wrong key** or
**corrupted ciphertext**, and the GUI reports it that way.

## Which modes use it

ECB and CBC must pad, because AES only accepts full blocks. CFB, OFB and CTR behave like stream
ciphers and could work without padding. To keep all five modes consistent with the specification,
this project pads in every mode.
