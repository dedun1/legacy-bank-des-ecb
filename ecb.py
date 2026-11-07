"""
ecb.py  -  Appendix B: the ECB weakness, shown with your own input.

Asks for a first text and puts it in the message three times, then asks for
a second text and puts it in once. The whole message is encrypted with
des.ecb_encrypt under the static key from client.py and server.py, and the
ciphertext of every block is printed: the three repeated blocks come out
identical, the single block comes out different.

Run:   python ecb.py
"""

import sys

import des

KEY = b"Iy4dB@nk"          # the static key from client.py / server.py
REPEATS = 3                # how many times the first text is put in the message


def ask(prompt: str) -> str:
    value = input(prompt)
    if not sys.stdin.isatty():
        print(value)              # typed input came from a file: show it on screen
    return value


def ask_block(prompt: str) -> bytes | None:
    """One DES block: 1 to 8 characters, filled up to 8 with spaces. None means quit."""
    while True:
        text = ask(prompt)
        if text.strip().lower() == "q":
            return None
        if 1 <= len(text) <= 8 and text.isascii():
            return text.ljust(8).encode()
        print("Type 1 to 8 normal characters (one DES block).")


def show(first: bytes, second: bytes) -> None:
    message = first * REPEATS + second
    ciphertext = des.ecb_encrypt(message, KEY)
    blocks = [ciphertext[i:i + 8] for i in range(0, len(ciphertext), 8)]

    print(f"Message: {message.decode()!r}  ({len(message)} bytes, {len(message) // 8} blocks + 1 padding block)")
    print()
    print("Block  Text        Ciphertext        Repeat?")
    for i, block in enumerate(blocks):
        if i < REPEATS:
            text, note = first.decode(), "no" if i == 0 else "yes, block 1 again"
        elif i == REPEATS:
            text = second.decode()
            note = "yes, block 1 again" if block == blocks[0] else "no"
        else:
            text, note = "(padding)", ""
        label = text if text == "(padding)" else repr(text)
        print(f"{i + 1:<6} {label:<11} {block.hex().upper()}  {note}".rstrip())
    print()

    print(f"{first.decode()!r} was sent {REPEATS} times and gave {blocks[0].hex().upper()} every time.")
    if second == first:
        print(f"{second.decode()!r} was sent once more and gave it again.")
    else:
        print(f"{second.decode()!r} was sent once and gave {blocks[REPEATS].hex().upper()}.")
    print("An attacker reading the ciphertext cannot read the text, but can see that")
    print(f"blocks 1 to {REPEATS} carry the same message. ECB leaks repeats.")


def main() -> None:
    print(f"ECB demo (DES, static key {KEY.decode()} = {KEY.hex().upper()}). Type q to quit.")
    while True:
        print()
        first = ask_block(f"First text, will be sent {REPEATS} times (up to 8 characters): ")
        if first is None:
            break
        second = ask_block("Second text, will be sent once (up to 8 characters): ")
        if second is None:
            break
        print()
        show(first, second)


if __name__ == "__main__":
    try:
        main()
    except EOFError:              # input ran out (for example a file of test inputs)
        pass
