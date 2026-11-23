"""
Command-line demo (run from the repository root):

    python -m aesmodes                      AES key schedule + round-by-round trace
    python -m aesmodes --key 000102...1f    ... with a 128-, 192- or 256-bit key
    python -m aesmodes modes                encrypt a sample message in all 5 modes
    python -m aesmodes modes "your text"    ... with your own message
    python -m aesmodes modes "text" --key 000102030405060708090a0b0c0d0e0f --counter 1

The GUI (coming in Step 8) shows the same information visually.
"""

import argparse

from .aes_core import AES, format_state
from .modes import MODE_NAMES, decrypt, encrypt

DEFAULT_KEY = "2b7e151628aed2a6abf7158809cf4f3c"
DEFAULT_COUNTER = "00000000000000000000000000000001"


def aes_demo(key_hex: str = DEFAULT_KEY) -> None:
    key = bytes.fromhex(key_hex)
    pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    aes = AES(key)

    print(f"AES-{aes.key_bits}: {aes.nr} rounds, {len(aes.w)} key words")
    print(f"Key expansion ({len(aes.w)} words, grouped per round key):")
    for r in range(aes.nr + 1):
        words = " ".join(bytes(aes.w[4 * r + j]).hex() for j in range(4))
        print(f"  round {r:2d}: {words}")

    trace: list = []
    ct = aes.encrypt_block(pt, trace)
    print("\nEncryption trace:")
    for t in trace:
        print(f"\n  round {t['round']:2d} - {t['step']}")
        for line in format_state(t["state"]).splitlines():
            print("    " + line)

    print(f"\nPlaintext : {pt.hex()}")
    print(f"Ciphertext: {ct.hex()}")
    print(f"Decrypted : {aes.decrypt_block(ct).hex()}")


def modes_demo(message: str, key_hex: str, counter: str) -> None:
    key = bytes.fromhex(key_hex)
    msg = message.encode("utf-8")
    print(f'Message : "{message}"  ({len(msg)} bytes)')
    print(f"Key     : {key.hex()}")
    print("IV      : 00000000000000000000000000000000  (CBC, CFB, OFB)")
    print(f"Counter : {counter}  (CTR)")

    for mode in MODE_NAMES:
        res = encrypt(mode, key, msg, counter=counter)
        back = decrypt(mode, key, res.output, counter=counter).output
        print(f"\n=== {mode} " + "=" * 60)
        print(f"  {res.steps[0].note}")
        print(f"  {'#':>2}  {'input block':32}  {'AES input':32}  {'AES output':32}  {'output block':32}")
        for s in res.steps:
            print(f"  {s.index:>2}  {s.block_in.hex()}  {s.aes_input.hex()}  "
                  f"{s.aes_output.hex()}  {s.block_out.hex()}")
        print(f"  ciphertext : {res.hex()}")
        print(f"  decrypts to: {back.decode('utf-8', errors='replace')!r}  "
              f"{'✔' if back == msg else '✘'}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m aesmodes", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command")
    m = sub.add_parser("modes", help="encrypt a message in all 5 modes")
    m.add_argument("message", nargs="?", default="AES modes: ECB, CBC, CFB, OFB, CTR!")
    m.add_argument("--key", default=DEFAULT_KEY, help="32, 48 or 64 hex digits")
    m.add_argument("--counter", default=DEFAULT_COUNTER, help="initial CTR counter (hex)")
    parser.add_argument("--key", default=DEFAULT_KEY,
                        help="key for the AES demo: 32, 48 or 64 hex digits")
    args = parser.parse_args()

    if args.command == "modes":
        try:
            modes_demo(args.message, args.key, args.counter)
        except ValueError as e:
            parser.error(str(e))
    else:
        try:
            aes_demo(args.key)
        except ValueError as e:
            parser.error(str(e))


if __name__ == "__main__":
    main()
