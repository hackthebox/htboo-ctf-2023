#!/usr/bin/env python3

from pwn import *
import os

context.binary = e = ELF("./machine", checksec=False)
e.write(e.sym.ghost, asm("ret"))
e.save("./machine-patched")
os.chmod("./machine-patched", 0o755)
p = process("./machine-patched")
print(p.readline().decode())
p.close()
os.remove("machine-patched")