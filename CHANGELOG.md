# Changelog

All notable changes to this project are documented here, one entry per development step.

## [0.7.0] – Step 11: the AES Encryptor
### Added
- A separate website, the **AES Encryptor** (https://aes-modes-project.github.io/aes-modes-of-operation/encryptor/):
  encrypt and decrypt real files and messages with any of the five modes and any key size, in the browser.
- `aesmodes/fastaes.py`: a table-based (T-table) AES, built from our own S-box and GF(2⁸) maths and
  checked against the teaching `AES` class. About 7× faster, so files of several MB are practical.
- `aesmodes/filecrypt.py`: streaming modes, password-based keys (PBKDF2-HMAC-SHA256, random salt),
  an HMAC-SHA256 integrity tag, the self-describing `.aesm` format, and a command-line tool.
- `aesmodes/web/encryptor/`: the website (page, design, and a Web Worker running Python with Pyodide).
- `tests/test_filecrypt.py` and site build checks (281 tests in total). The website was also
  tested end to end in a headless browser (every mode and key size, files, wrong passwords).
### Changed
- The learning app's menu links to the Encryptor.

## [0.6.0] – Step 10: the learning app online
### Added
- The learning app is published on GitHub Pages (https://aes-modes-project.github.io/aes-modes-of-operation/). It runs the project's own Python code in
  the browser with Pyodide, so it needs no installation and no server.
- `aesmodes/api.py`: the request handlers, now shared by the Flask server and the browser version.
- `tools/build_site.py`: builds the web version; `.github/workflows/pages.yml` runs the tests and
  publishes the site on every push to `main`.
- `tests/test_api_and_site.py`: handler tests, a standard-library-only check for the browser files,
  and build tests (214 tests in total).
### Changed
- MixColumns uses precomputed GF(2⁸) multiplication tables: about 5× faster (same results).
- The page uses relative paths and shows a loading screen while Python starts in the browser.

## [0.5.0] – Step 9: AES-192 and AES-256
### Added
- `aes_core.py`: the `AES` class now supports 128-, 192- and 256-bit keys (10, 12 or 14 rounds). The key
  expansion handles N<sub>k</sub> = 4, 6 and 8, including AES-256's extra SubWord step. `AES128` remains as
  another name for the class.
- All five modes accept 16-, 24- or 32-byte keys.
- Learning app: an AES-128 / 192 / 256 selector under every key field; the AES page, key expansion
  page (52 / 60 words, AES-256 SubWord step) and explanations adapt to the key size; the FIPS-197
  example button loads Appendix B, C.2 or C.3 depending on the size.
- `tests/test_key_sizes.py`: FIPS-197 A.2/A.3 and C.1–C.3, NIST SP 800-38A first blocks for every mode
  with AES-192/256, pycryptodome cross-checks, server tests (81 new tests, 204 in total).
- CLI: `python -m aesmodes --key <48 or 64 hex digits>`.

## [0.4.0] – Step 8: the learning app
### Added
- `aesmodes/web/`: an interactive learning app (`python -m aesmodes.web`), a Flask server plus a
  LaTeX-style web page with four sections: Inside AES (41 steps with per-operation visuals and
  explanations), Key expansion, Modes of operation (padding view, block diagrams with real values,
  encrypt/decrypt), and Experiments (ECB picture, bit flip, zero-IV leak, comparison table).
- `aesmodes/explain.py`: converts the core's intermediate values into step-by-step data.
- KaTeX 0.16 bundled in `aesmodes/web/static/vendor/katex/`, so formulas and Computer Modern fonts work offline.
- `tests/test_web.py`: server tests against FIPS-197 values and the modes library.
- `docs/web-app.md` and screenshots in `docs/images/`.
### Changed
- Decrypt functions accept `strip_padding=False` to inspect damaged ciphertexts (used by the bit-flip experiment).
- `requirements.txt` now includes Flask.

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
