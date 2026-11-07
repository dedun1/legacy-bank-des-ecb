# Milestone 2 code: DES-ECB tunnel between the Legacy Bank mobile app and mainframe

Five files, Python 3 only, **no cryptography library** anywhere.

| File | What it does | Used for |
|---|---|---|
| `des.py` | DES written from the FIPS 46-3 tables: key schedule, 16 Feistel rounds, S-boxes, PKCS#7 padding, ECB mode, and the round-1 trace printer | The cipher both programs use |
| `server.py` | The mainframe: listens on 127.0.0.1:5000, receives the ciphertext, decrypts it with the static key, prints the transaction and replies that it was logged | Brief requirement, report Figure 2 |
| `client.py` | The mobile app: asks for an account number and an amount, encrypts `account | amount` with DES-ECB under the static key, sends it, prints the reply. Repeats until you type q | Brief requirement, report Figure 3 |
| `verify.py` | Proves des.py is real DES (7 published test vectors, 2,000 random round trips, padding), then prints every value of round 1 and the state after all 16 rounds | Figures 4, 5 and 6, Appendix A |
| `ecb.py` | Asks for a first text (sent 3 times) and a second text (sent once), encrypts them with DES-ECB and shows that the repeats give identical ciphertext blocks | Appendix B, Figure 7 |

The 64-bit key `Iy4dB@nk` is hardcoded in both `client.py` and `server.py`, as the brief requires.

## Run

Terminal 1:
```
python server.py
```
Terminal 2:
```
python client.py
```
Type an account number (digits) and an amount, as many times as you like, then `q` to quit. The client prints each block's plaintext and ciphertext and round 1 of block 1; the server prints the decrypted transaction and replies.

Evidence scripts:
```
python verify.py            tests, then the round-1 trace and all 16 rounds
python verify.py --trace    only the trace
python ecb.py               Appendix B: type a first text, then a second text, then q
```

Stop the server with Ctrl+C. On Windows use `python` (or `py -3`), not `python3`.
