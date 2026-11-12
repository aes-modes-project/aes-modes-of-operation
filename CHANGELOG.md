# Changelog

All notable changes to this project are documented here, one entry per development step.

## [0.3.0] – Steps 4–7: CBC, CFB, OFB and CTR
### Added
- `aesmodes/modes.py`: CBC, CFB (full-block), OFB and CTR, each with encrypt/decrypt and per-block
  `BlockStep` records; `encrypt()` / `decrypt()` entry points for any mode; zero IV by default;
  CTR initial counter accepted as a hex string, int or 16 bytes (wraps mod 2^128).
- `tests/test_modes.py`: NIST SP 800-38A vectors (F.2.1, F.3.13, F.4.1, F.5.1), pycryptodome
  comparison, round trips for every mode, counter handling, and error-propagation tests.
- Docs: `docs/cbc.md`, `docs/cfb.md`, `docs/ofb.md`, `docs/ctr.md`, `docs/modes-comparison.md`.
- CLI: `python -m aesmodes modes "message"` encrypts a message in all five modes, block by block.

## [0.2.0] – Step 2 & 3: padding and ECB
### Added
- `aesmodes/padding.py`: zeros + pad-count padding (ANSI X.923 style), with validation on removal.
- `aesmodes/modes.py`: ECB encryption and decryption, plus the `ModeResult` / `BlockStep` structures
  that record each block for the GUI.
- Tests: `tests/test_padding.py`, `tests/test_ecb.py` (NIST SP 800-38A F.1.1 vectors, ECB-pattern demo).
- Docs: `docs/padding.md`, `docs/ecb.md`.

## [0.1.0] – Step 1: AES-128 core
### Added
- `aesmodes/aes_core.py`: AES-128 from scratch (computed S-box, key expansion, round operations,
  encrypt/decrypt one block, optional step-by-step trace).
- `aesmodes/__main__.py`: command-line demo (`python -m aesmodes`).
- Tests against FIPS-197 vectors and pycryptodome.
- Project setup: README, docs, pyproject, requirements, .gitignore, MIT license.
