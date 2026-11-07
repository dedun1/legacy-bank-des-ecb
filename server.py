"""
server.py  -  Legacy Bank mainframe side, Milestone 2.

Listens on a TCP port, receives DES-ECB ciphertext from client.py, decrypts it
with the static key both programs were built with, prints the transaction and
replies that it was logged.

Run:   python server.py            (listens on 127.0.0.1:5000)

The static key and ECB mode are deliberate: they are the Milestone 2
requirement, and their weaknesses are evaluated in the report.
"""

import socket
import struct

import des

HOST, PORT = "127.0.0.1", 5000
STATIC_KEY = b"Iy4dB@nk"          # 8 ASCII bytes = 64 bits (56 used), must match client.py
HEADER = struct.Struct("!I")      # 4-byte length in front of every message


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes; TCP may deliver them in several pieces."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed the connection")
        buf += chunk
    return buf


def recv_frame(sock: socket.socket) -> bytes:
    (length,) = HEADER.unpack(recv_exact(sock, HEADER.size))
    return recv_exact(sock, length)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(HEADER.pack(len(payload)) + payload)


def handle(conn: socket.socket, addr, count: int) -> int:
    print(f"\nApp connected ({addr[0]}:{addr[1]})")
    while True:
        try:
            ciphertext = recv_frame(conn)
        except ConnectionError:
            print("App disconnected")
            return count
        count += 1
        blocks = " ".join(ciphertext[i:i + 8].hex().upper()
                          for i in range(0, len(ciphertext), 8))
        text = des.ecb_decrypt(ciphertext, STATIC_KEY).decode()
        account, amount = text.split(" | ")
        reply = f"OK, transaction {count} logged"
        print()
        print(f"Transaction {count} received ({len(ciphertext)} bytes): {blocks}")
        print(f"Decrypted: {text}")
        print(f"Account {account}, amount {amount} EGP")
        send_frame(conn, reply.encode())
        print(f"Replied: {reply}")


def main() -> None:
    print("Legacy Bank mainframe (DES-ECB, static key "
          f"{STATIC_KEY.decode()} = {STATIC_KEY.hex().upper()})")
    count = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)
        print(f"Waiting for the app on {HOST}:{PORT}")
        while True:
            conn, addr = srv.accept()
            with conn:
                count = handle(conn, addr, count)


if __name__ == "__main__":
    main()
