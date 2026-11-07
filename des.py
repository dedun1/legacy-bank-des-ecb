"""
des.py  -  DES written from scratch (FIPS 46-3) for Legacy Bank, Milestone 2.
Written by hand, not imported, so Appendix A can be checked against the same code
that encrypts the live traffic. verify.py proves it matches published DES answers.
Bits are kept as a list of 0/1 ints, bit 1 on the left; tables are 1-based as in FIPS 46-3.
"""

IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,  # initial permutation
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,  # final permutation (IP reversed)
      38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,  # expansion: 32 -> 48 bits
     12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,  # shuffles the S-box output
     2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,  # drops 8 parity bits: 64 -> 56
       10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,  # picks 48 of 56 bits per round key
       26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
       51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]  # left rotation per round
SBOX = [  # 8 boxes x 4 rows x 16 columns
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0], [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10], [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15], [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8], [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7], [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15], [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4], [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9], [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14], [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11], [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6], [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1], [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2], [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7], [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8], [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]
BLOCK_SIZE = 8  # DES works on 8 bytes = 64 bits

def bytes_to_bits(data):  # b'A' -> [0,1,0,0,0,0,0,1]
    return [(byte >> (7 - i)) & 1 for byte in data for i in range(8)]

def bits_to_bytes(bits):  # groups of 8 bits back into bytes
    return bytes(int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8))

def int_to_bits(value, width):  # int_to_bits(5, 4) -> [0,1,0,1]
    return [(value >> (width - 1 - i)) & 1 for i in range(width)]

def permute(bits, table):  # output bit n = input bit table[n]
    return [bits[position - 1] for position in table]  # -1: tables count from 1

def xor(a, b):  # equal bits -> 0, different -> 1
    return [x ^ y for x, y in zip(a, b)]

def rotate_left(bits, n):  # first n bits move to the end
    return bits[n:] + bits[:n]

def bitstr(bits, group=4):  # '0101 1100 ...' for printing
    s = "".join(map(str, bits))
    return " ".join(s[i:i + group] for i in range(0, len(s), group))

def key_schedule(key):  # 8-byte key -> 16 round keys K1..K16
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes (64 bits)")
    key56 = permute(bytes_to_bits(key), PC1)  # PC-1: drop parity bits
    c, d = key56[:28], key56[28:]  # C0 = left 28, D0 = right 28
    subkeys = []
    for shift in SHIFTS:
        c, d = rotate_left(c, shift), rotate_left(d, shift)  # rotate 1 or 2 places
        subkeys.append(permute(c + d, PC2))  # PC-2: 48-bit round key
    return subkeys

def sbox_lookup(box_index, six_bits):  # returns (row, column, value)
    row = (six_bits[0] << 1) | six_bits[5]  # row = outer bits b1 b6 (0..3)
    col = int("".join(map(str, six_bits[1:5])), 2)  # column = b2..b5 (0..15)
    return row, col, SBOX[box_index][row][col]

def feistel(right, subkey):  # round function f(R, K)
    mixed = xor(permute(right, E), subkey)  # expand 32 -> 48, XOR the key
    sbox_out = []
    for i in range(8):  # eight 6-bit groups, one per S-box
        value = sbox_lookup(i, mixed[i * 6:i * 6 + 6])[2]  # S-box i: 6 bits in
        sbox_out += int_to_bits(value, 4)  # 4 bits out
    return permute(sbox_out, P)  # 32 bits

def des_rounds(block, subkeys):  # IP, 16 rounds, swap, FP
    if len(block) != BLOCK_SIZE:
        raise ValueError("DES block must be exactly 8 bytes")
    bits = permute(bytes_to_bits(block), IP)
    left, right = bits[:32], bits[32:]  # L0 and R0
    for subkey in subkeys:
        left, right = right, xor(left, feistel(right, subkey))  # L = R, R = L xor f
    return bits_to_bytes(permute(right + left, FP))  # swap halves, then FP

def encrypt_block(block, key):  # rounds with K1 ... K16
    return des_rounds(block, key_schedule(key))

def decrypt_block(block, key):  # same rounds with K16 ... K1
    return des_rounds(block, key_schedule(key)[::-1])

def pad(data):  # PKCS#7: add n bytes of value n
    n = BLOCK_SIZE - (len(data) % BLOCK_SIZE)  # always 1..8 bytes
    return data + bytes([n]) * n

def unpad(data):  # check and strip the padding
    n = data[-1] if data else 0
    if len(data) % BLOCK_SIZE or not 1 <= n <= BLOCK_SIZE or data[-n:] != bytes([n]) * n:
        raise ValueError("invalid padding")
    return data[:-n]

def ecb_encrypt(data, key):  # ECB: each block alone, same key
    padded = pad(data)
    blocks = [padded[i:i + 8] for i in range(0, len(padded), 8)]  # 8-byte blocks
    return b"".join(encrypt_block(block, key) for block in blocks)  # same key each time

def ecb_decrypt(data, key):  # decrypt each block, then unpad
    if len(data) % BLOCK_SIZE:
        raise ValueError("ciphertext length is not a multiple of 8")
    return unpad(b"".join(decrypt_block(data[i:i + 8], key) for i in range(0, len(data), 8)))

def format_round1_trace(block, key):  # every value of round 1 (Appendix A)
    hx = lambda bits: bits_to_bytes(bits).hex()
    key_bits = bytes_to_bits(key)
    key56 = permute(key_bits, PC1)
    c0, d0 = key56[:28], key56[28:]
    c1, d1 = rotate_left(c0, 1), rotate_left(d0, 1)
    k1 = permute(c1 + d1, PC2)  # round key 1
    plain_bits = bytes_to_bits(block)
    ip_bits = permute(plain_bits, IP)
    l0, r0 = ip_bits[:32], ip_bits[32:]
    expanded = permute(r0, E)
    mixed = xor(expanded, k1)
    lookups = [sbox_lookup(i, mixed[i * 6:(i + 1) * 6]) for i in range(8)]
    sbox_out = sum((int_to_bits(v, 4) for _, _, v in lookups), [])
    f_out = permute(sbox_out, P)
    l1, r1 = r0, xor(l0, f_out)  # the Feistel step
    rows = [f"   S{i}   {''.join(map(str, mixed[(i - 1) * 6:i * 6]))}   {r}   {c:2d}   {v:2d} = {v:04b}"
            for i, (r, c, v) in enumerate(lookups, start=1)]
    return "\n".join([
        "DES round 1, step by step",
        f"Plaintext block : {block!r}  = {block.hex()}", f"Key             : {key!r}  = {key.hex()}", "",
        "1. Plaintext as 64 bits (byte order, MSB first)", "   " + bitstr(plain_bits, 8), "",
        "2. Initial Permutation IP -> L0 | R0", "   IP out: " + bitstr(ip_bits, 8),
        "   L0    : " + bitstr(l0) + "  = " + hx(l0), "   R0    : " + bitstr(r0) + "  = " + hx(r0), "",
        "3. Key schedule", "   Key 64 bits : " + bitstr(key_bits, 8), "   PC-1 (56 b) : " + bitstr(key56, 7),
        "   C0          : " + bitstr(c0, 7), "   D0          : " + bitstr(d0, 7),
        "   C1 = C0<<<1 : " + bitstr(c1, 7), "   D1 = D0<<<1 : " + bitstr(d1, 7),
        "   K1 = PC-2(C1 D1), 48 bits:", "   " + bitstr(k1, 6) + "  = " + hx(k1), "",
        "4. Round function f(R0, K1)", "   E(R0) 48 b  : " + bitstr(expanded, 6),
        "   K1          : " + bitstr(k1, 6), "   E(R0) xor K1: " + bitstr(mixed, 6), "",
        "   S-box lookups (row = outer bits b1b6, column = inner bits b2b3b4b5)",
        "   box  input    row col  output", *rows,
        "   S-box output (32 b): " + bitstr(sbox_out) + "  = " + hx(sbox_out),
        "   P(S out) = f     : " + bitstr(f_out) + "  = " + hx(f_out), "",
        "5. Round output", "   L1 = R0          : " + bitstr(l1) + "  = " + hx(l1),
        "   R1 = L0 xor f    : " + bitstr(r1) + "  = " + hx(r1),
        "   L1 | R1 (64 b)   : " + bitstr(l1 + r1, 8), f"   as hex           : {hx(l1 + r1)}", "",
        "6. Check: running the real cipher for ONE round (with the final swap and",
        "   inverse IP applied) gives: " + hx(permute(r1 + l1, FP)),
        "   The full 16-round ciphertext for this block is: " + encrypt_block(block, key).hex()])

def format_all_rounds(block, key):  # L and R after each of the 16 rounds
    hx = lambda bits: bits_to_bytes(bits).hex()
    bits = permute(bytes_to_bits(block), IP)
    left, right = bits[:32], bits[32:]
    lines = ["All 16 rounds (the cipher always runs every round)",
             "  round  subkey K_i (48 bits)  L_i        R_i", f"  {0:>5}  {'(after IP)':<20}  {hx(left)}  {hx(right)}"]
    for n, subkey in enumerate(key_schedule(key), start=1):
        left, right = right, xor(left, feistel(right, subkey))  # same line as in des_rounds
        lines.append(f"  {n:>5}  {hx(subkey):<20}  {hx(left)}  {hx(right)}")
    return "\n".join(lines + ["", f"  swap halves  : R16 L16 = {hx(right)} {hx(left)}",
                              f"  apply FP     : ciphertext = {hx(permute(right + left, FP))}",
                              f"  encrypt_block: ciphertext = {encrypt_block(block, key).hex()}  (same)"])

if __name__ == "__main__":  # quick self test: python des.py
    c = encrypt_block(b"Learning", b"Iy4dB@nk")
    print("plain : Learning", b"Learning".hex())
    print("cipher:", c.hex(), "| back:", decrypt_block(c, b"Iy4dB@nk"))
