![](https://github.com/hackthebox/writeup-templates/raw/master/challenge/assets/images/banner.png)

<img src="https://github.com/hackthebox/writeup-templates/raw/master/challenge/assets/images/htb.png" style="margin-left: 20px; zoom: 80%;" align=left/>
<font size="10">GhostInTheMachine</font>
12<sup>th</sup> 09 23 / Document No. D22.102.XX
Prepared By: clubby789
Challenge Author: clubby789
Difficulty: <font color=green>Very Easy</font>
Classification: Official

# Synopsis

GhostInTheMachine is an Very Easy reversing challenge. Players will use debugging or binary patching to recover a flag.

## Skills Required
    - Basic decompiler use
## Skills Learned
    - Debugging
    - Binary Patching

# Solution

If we run the provided binary, we'll receive some garbled bytes, different every time. We'll open the binary in a decompiler.

## Decompilation

The binary is rather small.

```c
int32_t main(int32_t argc, char** argv, char** envp)
    char buf[0x80]
    __builtin_memset(s: &buf, c: 0, n: 0x80)
    getflag(&buf)
    ghost(&buf)
    puts(str: &buf)
```

The `getflag` function consists of placing bytes into a buffer in a random order.

```c
void getflag(char* arg1)
    arg1[0xf] = 0x74
    arg1[1] = 0x54
    arg1[0x18] = 0x6e
    arg1[2] = 0x42
    [ .. SNIP ..]
```

Finally, the `ghost` function XORs the `flag` with random data.
```c
void ghost(char* flag)
    char* flag_1 = flag
    int32_t fd = open(file: "/dev/urandom", oflag: 0)
    // until we reach a null byte
    while (*flag_1 != 0) {
        char buf
        do {
            // get a random byte in 'buf'
            read(fd, buf: &buf, nbytes: 1)
        } while (*flag_1 == buf) // if it's the same as the current byte, continue
        char* flag_2 = flag_1
        // progress to next byte
        flag_1 = &flag_2[1]
        // xor current byte with `buf`
        *flag_2 = buf ^ *flag_2
    }
    close(fd)
```

The scrambled flag is then printed.

## Solving

To solve the challenge, we can either transcribe the values assigned in `getflag` and reorder them, debug to view the contents of the buffer after `getflag` is run, or patch the binary to prevent the `ghost` function running at all.

I'll demonstrate patching with an automated solution. First, we'll import `pwntools` and open the binary.

```py
from pwn import *
context.binary = e = ELF("./machine", checksec=False)
```

We can then overwrite the `ghost` function with a `ret` instruction to essentially disable it, before saving a patched version.

```py
e.write(e.sym.ghost, asm("ret"))
e.save("./machine-patched")
```

We can then run the patched version to print out the flag.