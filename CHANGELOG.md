# Changelog

All notable changes to this project are documented here, one entry per development step.

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
