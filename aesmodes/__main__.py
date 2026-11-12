"""
Command-line demo:  python -m aesmodes   (run from the repository root)

Prints the AES-128 key schedule and the full round-by-round encryption trace
for the FIPS-197 Appendix B example, then decrypts the result.
"""

from .aes_core import AES128, NR, format_state


def demo() -> None:
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    aes = AES128(key)

    print("Key expansion (44 words, grouped per round key):")
    for r in range(NR + 1):
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


if __name__ == "__main__":
    demo()
