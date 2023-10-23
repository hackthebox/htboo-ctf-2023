from Crypto.Util.Padding import unpad
from Crypto.Util import Counter
from pwn import xor
from Crypto.Util.Padding import pad

with open('messages.txt') as f:
    MSG = [pad(m.encode(), 16) for m in eval(f.read())]

with open('output.txt') as f:
    cts = [bytes.fromhex(line.strip()) for line in f.readlines()]

def blocks(m):
    return [m[i:i+16] for i in range(0, len(m), 16)]

M = [blocks(m) for m in MSG]
C = [blocks(c) for c in cts]

F0 = xor(C[2][0], C[1][1], M[1][1])
F1 = xor(C[2][1], C[1][2], M[1][2])
F2 = xor(C[2][2], C[3][1], M[3][1])
F3 = xor(C[2][3], C[3][2], M[3][2])

flag = (F0 + F1 + F2 + F3).decode()

print(flag)
