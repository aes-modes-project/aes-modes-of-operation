# AES Modes of Operation

**EECE 455/632 – Cryptography and Network Security · Project 8**

An educational implementation of **AES-128** written from scratch in Python, together with its five
classic **modes of operation**: ECB, CBC, CFB, OFB and Counter (CTR). A desktop GUI with a
LaTeX-inspired look shows every step of the encryption so students can see *how* each mode works,
not just the final ciphertext.

> ⚠️ **Educational use only.** This project follows the course specification (for example, an
> all-zero IV), which is deliberately predictable so results can be checked by hand. Do not use it to
> protect real data; use a vetted library such as `cryptography` or `pycryptodome` instead.

---

## Project specification

> *Implement AES in 5 modes: ECB, CBC, CFB, OFB, and Counter mode where the user will set the initial
> counter value (padding of last block should be done with zeroes along with count of pad size;
> Initial vectors should be set to zeroes).*

| Requirement | How it is implemented |
|---|---|
| Block cipher | AES-128 (FIPS-197), implemented from scratch: no crypto library is used for encryption |
| Modes | ECB, CBC, CFB, OFB, CTR |
| Initial vector | 16 zero bytes (`00…00`) for CBC, CFB and OFB |
| Counter | 128-bit initial value entered by the user, incremented by 1 per block (mod 2¹²⁸) |
| Padding | Zero bytes, last byte = number of padding bytes (ANSI X.923 style), see [docs/padding.md](docs/padding.md) |

## Roadmap

- [x] **Step 1 – AES-128 core**: key expansion, round operations, encrypt/decrypt one block, step trace
- [x] **Step 2 – Padding**: zeros + pad-count byte
- [x] **Step 3 – ECB mode**
- [x] **Step 4 – CBC mode**
- [x] **Step 5 – CFB mode** (full-block, CFB-128)
- [x] **Step 6 – OFB mode**
- [x] **Step 7 – CTR mode** (user-defined initial counter)
- [ ] **Step 8 – GUI** (PySide6, LaTeX-style typography, step-by-step view)
- [ ] **Step 9 – Report material**: mode comparison ([started](docs/modes-comparison.md)), ECB-pattern and error-propagation demos

## Repository structure

```
aes-modes-of-operation/
├── aesmodes/              # the Python package
│   ├── __init__.py
│   ├── __main__.py        # command-line demo (python -m aesmodes)
│   ├── aes_core.py        # AES-128 block cipher (one 16-byte block)
│   ├── padding.py         # zeros + pad-count padding
│   └── modes.py           # ECB, CBC, CFB, OFB, CTR
├── tests/
│   ├── test_aes_core.py   # FIPS-197 test vectors + random cross-checks
│   ├── test_padding.py
│   ├── test_ecb.py        # ECB: NIST SP 800-38A F.1.1
│   └── test_modes.py      # CBC/CFB/OFB/CTR: NIST vectors, error propagation
├── docs/
│   ├── aes-core.md        # how the AES core is built
│   ├── padding.md         # the padding scheme
│   ├── ecb.md             # one page per mode ...
│   ├── cbc.md
│   ├── cfb.md
│   ├── ofb.md
│   ├── ctr.md
│   └── modes-comparison.md   # all five modes side by side
├── CHANGELOG.md           # what changed in each step
├── requirements.txt       # runtime dependencies
├── requirements-dev.txt   # testing dependencies
├── pyproject.toml         # project metadata + pytest configuration
├── .gitignore
├── LICENSE
└── README.md
```

## Getting started

Requires **Python 3.10+**.

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements-dev.txt

# 3. Run the tests
python -m pytest -v

# 4. See the AES core in action (key schedule + round-by-round trace)
python -m aesmodes

# 5. Encrypt a message in all five modes, block by block
python -m aesmodes modes "Hello, AES modes!"
python -m aesmodes modes "Hello" --key 000102030405060708090a0b0c0d0e0f --counter ff
```

In VS Code: open the folder, press `⇧⌘P` → **Python: Select Interpreter** → choose `.venv`, then
use the **Testing** sidebar to run the tests.

## Usage (library)

```python
from aesmodes import AES128, format_state

aes = AES128(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))

trace = []                                     # optional: collect every intermediate state
ct = aes.encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff"), trace)
print(ct.hex())                                # 69c4e0d86a7b0430d8cdb78070b4c55a

for step in trace[:3]:
    print(step["round"], step["step"])
    print(format_state(step["state"]))
```

### Encrypting a message with a mode

```python
from aesmodes import encrypt, decrypt

key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

res = encrypt("CBC", key, b"Hello, AES modes!")         # zero IV, zero+count padding
print(res.hex())                                        # 32 bytes: 17 + 15 padding
for s in res.steps:                                     # what happened to each block
    print(s.index, s.note)
    print("   in ", s.block_in.hex(), " xor ", s.xor_with.hex())
    print("   AES", s.aes_input.hex(), "->", s.aes_output.hex())
    print("   out", s.block_out.hex())

print(decrypt("CBC", key, res.output).output)           # b'Hello, AES modes!'

# CTR mode: the user chooses the initial counter (hex string, int or 16 bytes)
ct = encrypt("CTR", key, b"Hello", counter="f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").output
print(decrypt("CTR", key, ct, counter="f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").output)
```

Each mode also has its own functions (`cbc_encrypt`, `ctr_decrypt`, …). `ModeResult` holds the
output, the padded data, the IV or counter used, and one `BlockStep` per block.

## Verification

The AES core is checked against the official **FIPS-197** test vectors (key expansion, Appendix B and
Appendix C.1) and against `pycryptodome` on hundreds of random keys and blocks.

All five modes are checked against the **NIST SP 800-38A** test vectors (F.1.1, F.2.1, F.3.13, F.4.1,
F.5.1), against `pycryptodome` with the zero IV, with round trips for many message lengths, and with
error-propagation tests that confirm the behaviour described in
[docs/modes-comparison.md](docs/modes-comparison.md). Run `python -m pytest -v` to see all 107 tests.

## References

- NIST **FIPS-197**, *Advanced Encryption Standard (AES)*
- NIST **SP 800-38A**, *Recommendation for Block Cipher Modes of Operation*
- W. Stallings, *Cryptography and Network Security: Principles and Practice*

## License

MIT, see [LICENSE](LICENSE).
