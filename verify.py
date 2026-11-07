"""
verify.py  -  proves that des.py is a correct DES, then prints the Appendix A
values: every intermediate step of round 1 and the state after all 16 rounds.

No cryptography library is used anywhere in Milestone 2, including here. The
reference answers are published DES test vectors (known-answer tests), so if
des.py gives the published ciphertext for every one, it is standard DES.

Part 1, the tests:
  1. Seven published known-answer test vectors: encrypt must give the
     published ciphertext and decrypt must give the plaintext back.
  2. 2000 random (key, block) pairs: decrypt(encrypt(x)) must equal x.
  3. ECB with PKCS#7 padding round-trips for message lengths 0..39.

Part 2, the trace: round 1 step by step for the block worked by hand in
Appendix A ("Learning") under the static key from client.py.

Run:  python verify.py           (standard library only, nothing to install)
      python verify.py --trace   (skip the tests, print only the trace)
"""

import os
import sys
import des

BLOCK = b"Learning"     # the 8-byte block worked by hand in Appendix A
KEY = b"Iy4dB@nk"       # the static key from client.py / server.py

# (key, plaintext, expected ciphertext, where the vector is published)
VECTORS = [
    ("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405",
     "Grabbe, 'The DES Algorithm Illustrated'"),
    ("0E329232EA6D0D73", "8787878787878787", "0000000000000000",
     "Grabbe, 'The DES Algorithm Illustrated'"),
    ("0123456789ABCDEF", "4E6F772069732074", "3FA40E8A984D4815",
     "classic 'Now is t' example (FIPS 81 era)"),
    ("0101010101010101", "8000000000000000", "95F8A5E5DD31D900",
     "NIST SP 800-17, variable plaintext test"),
    ("0101010101010101", "0000000000000001", "166B40B44ABA4BD6",
     "NIST SP 800-17, variable plaintext test"),
    ("8001010101010101", "0000000000000000", "95A8D72813DAA94D",
     "NIST SP 800-17, variable key test"),
    ("7CA110454A1A6E57", "01A1D6D039776742", "690F5B0D9A26939B",
     "NIST SP 800-17, substitution table test"),
]


def test_known_vectors():
    for key_hex, plain_hex, cipher_hex, source in VECTORS:
        key, plain = bytes.fromhex(key_hex), bytes.fromhex(plain_hex)
        expected = bytes.fromhex(cipher_hex)
        assert des.encrypt_block(plain, key) == expected, f"encrypt failed: {source}"
        assert des.decrypt_block(expected, key) == plain, f"decrypt failed: {source}"
        print(f"OK  key {key_hex}  {plain_hex} -> {cipher_hex}   ({source})")


def test_round_trip(n=2000):
    for _ in range(n):
        key, block = os.urandom(8), os.urandom(8)
        assert des.decrypt_block(des.encrypt_block(block, key), key) == block
    print(f"OK  {n} random blocks: decrypt(encrypt(x)) == x")


def test_ecb_padding():
    for length in range(0, 40):
        msg = os.urandom(length)
        assert des.ecb_decrypt(des.ecb_encrypt(msg, KEY), KEY) == msg
    print("OK  ECB round trip with PKCS#7 padding for lengths 0..39")


def run_tests():
    test_known_vectors()
    test_round_trip()
    test_ecb_padding()
    print("All DES tests passed (no cryptography library used).")


def run_trace():
    print(des.format_round1_trace(BLOCK, KEY))
    print()
    print(des.format_all_rounds(BLOCK, KEY))


if __name__ == "__main__":
    if "--trace" in sys.argv:
        run_trace()
    else:
        run_tests()
        print()
        run_trace()
