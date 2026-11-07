"""
client.py  -  Legacy Bank mobile app side, Milestone 2.

Asks for an account number and an amount, encrypts the transaction with DES in
ECB mode under the static key, sends the ciphertext over TCP to the mainframe
(server.py) and prints the server's reply. Repeats until you type q.

Run:   python client.py
"""

import socket
import struct
import sys

import des

HOST, PORT = "127.0.0.1", 5000
STATIC_KEY = b"Iy4dB@nk"          # 8 ASCII bytes = 64 bits, must match server.py
HEADER = struct.Struct("!I")      # 4-byte length sent in front of every message


def ask(prompt: str) -> str:
    value = input(prompt).strip()
    if not sys.stdin.isatty():
        print(value)              # typed input came from a file: show it on screen
    return value


def is_amount(text: str) -> bool:
    try:
        return float(text) > 0
    except ValueError:
        return False


def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(HEADER.pack(len(payload)) + payload)  # length first: TCP is a byte stream


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("server closed the connection")
        buf += chunk
    return buf


def round1(block: bytes) -> tuple[str, str]:
    """L1 and R1 after round 1, the values worked by hand in Appendix A."""
    bits = des.permute(des.bytes_to_bits(block), des.IP)
    l0, r0 = bits[:32], bits[32:]
    r1 = des.xor(l0, des.feistel(r0, des.key_schedule(STATIC_KEY)[0]))
    return des.bits_to_bytes(r0).hex().upper(), des.bits_to_bytes(r1).hex().upper()


def main() -> None:
    print("Legacy Bank mobile app (DES-ECB, static key "
          f"{STATIC_KEY.decode()} = {STATIC_KEY.hex().upper()})")
    count = 0
    with socket.create_connection((HOST, PORT)) as sock:
        print(f"Connected to the mainframe at {HOST}:{PORT}. Type q to quit.")
        while True:
            print()
            account = ask("Account number: ")
            if account.lower() in ("q", "quit"):
                print("Bye.")
                break
            if not account.isdigit():
                print("Account number must be digits only.")
                continue
            amount = ask("Amount (EGP): ")
            if not is_amount(amount):
                print("Amount must be a number above 0.")
                continue

            count += 1
            message = f"{account} | {amount}".encode()
            padded = des.pad(message)
            ciphertext = des.ecb_encrypt(message, STATIC_KEY)
            n = len(padded) // 8
            print(f"Transaction {count}: {message.decode()}")
            added = len(padded) - len(message)
            print(f"Padded: {len(message)} bytes + {added} = {len(padded)} bytes ({n} blocks)")
            for i in range(n):
                p = padded[i * 8:i * 8 + 8].hex().upper()
                c = ciphertext[i * 8:i * 8 + 8].hex().upper()
                note = "  (has the padding)" if i == n - 1 else ""
                print(f"Block {i + 1}  {p}  encrypts to  {c}{note}")
            l1, r1 = round1(padded[:8])
            print(f"Round 1 of block 1: L1 = {l1}, R1 = {r1}")

            send_frame(sock, ciphertext)
            (length,) = HEADER.unpack(recv_exact(sock, HEADER.size))
            reply = recv_exact(sock, length).decode()
            print(f"Sent {len(ciphertext)} bytes. Mainframe says: {reply}")


if __name__ == "__main__":
    try:
        main()
    except EOFError:              # input ran out (for example a file of test inputs)
        pass
