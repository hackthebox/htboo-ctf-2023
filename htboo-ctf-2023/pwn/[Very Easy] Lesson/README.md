![](assets/banner.png)



<img src="assets/htb.png" style="margin-left: 20px; zoom: 80%;" align=left />    	<font size="10">Lesson</font>

​		26<sup>th</sup> September 2023 / Document No. DYY.102.XX

​		Prepared By: w3th4nds

​		Challenge Author(s): w3th4nds

​		Difficulty: <font color=green>Easy</font>

​		Classification: Official

 



# Synopsis

Lesson is an easy difficulty challenge that features analyzing C code and answering some questions to get the flag.

# Description

It's time to learn some basic things about binaries and basic c. Answer some questions to get the flag.

## Skills Required

- N/A

## Skills Learned

- Basic C.

# Enumeration

We are given a `.zip` file that contains a `README.txt`, a `binary`, its `source code` and a `glibc` folder.

```console
challenge git:main ❯ l                                                                                      
glibc/  main*  main.c  README.txt
```

Reading `README.txt` tells us that we don't need to pwn the actual binary, just answer some questions based on it.

> For this challenge, you do not have to pwn the given binary to get the flag.
> Answer the questions based on the program and you will be rewarded with the flag.
> Connect to the remote instance with: $ nc <IP> <PORT> e.g. nc localhost 1337

The source code is this:

```c
#include <stdio.h>

void under_construction(){
  printf("This is under development\n");
}

void print_msg(char *user){
  char formatter[0x20];
  strncpy(formatter, user, 5);
  for (size_t i = 0; i < 5; i++) formatter[i] = tolower(formatter[i]);
  printf(strncmp(formatter, "admin", 5) == 0 ? "\nWelcome admin!\n\n" : "\nWelcome user!\n\n");  
}

int main(int argc, char **argv){
  char name[0x20] = {0};
  unsigned long x, y;
  printf("Enter your name: ");
  scanf("%s", name);
  print_msg(name);
  return 0;
}
```

Now, connecting to the remote instance we see some **HINTS** and the corresponding question.

```console
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉
◉                                                                     ◉
◉  HINT: Run 'file ./main' to get some information about the binary.  ◉
◉                                                                     ◉
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉

[*] Question number 0x1:

Is this a '32-bit' or '64-bit' ELF? (e.g. 1337-bit)

>> 32-bit

♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠
♠                 ♠
♠      Wrong      ♠
♠                 ♠
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠

[*] Question number 0x1:

Is this a '32-bit' or '64-bit' ELF? (e.g. 1337-bit)
```

If the answer is wrong, the question is repeated. Once the answer is correct, it proceeds to the next question. I will give answer to all questions and then provide a solver to automate the process.

#### Question 1

```console
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉
◉                                                                     ◉
◉  HINT: Run 'file ./main' to get some information about the binary.  ◉
◉                                                                     ◉
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉

[*] Question number 0x1:

Is this a '32-bit' or '64-bit' ELF? (e.g. 1337-bit)
```

Running the `file` command, we see that the binary is `64-bit`.

```console
challenge git:main ❯ file main                                                                               
main: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc/ld-linux-x86-64.so.2, BuildID[sha1]=da663acb70f9fa157a543a6c4affd05e53fbcb07, for GNU/Linux 3.2.0, not stripped
```

#### Question 2

```console
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉
◉                                                                   ◉
◉  HINT: Run 'gdb ./main' to open the binary in the debugger, then  ◉
◉        run 'checksec' to see the protections.                     ◉
◉                                                                   ◉
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉

[*] Question number 0x2:

Which of these 3 protections are enabled (Canary, NX, PIE)?
```

We open the debugger as the program prompts us and type `checksec`.

```gdb
pwndbg> checksec
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./glibc/'
```

From the 3 protections mentioned, only `NX` is enabled.

#### Question 3

```console
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉
◉                                                           ◉
◉  HINT: Pay attention to the 'void print_msg(char *user)'  ◉
◉        and the 'strncmp(arg1, arg2, n_bytes)'.            ◉
◉                                                           ◉
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉

[*] Question number 0x3:

What do you need to enter so the message 'Welcome admin!' is printed?
```

Taking a look at this function:

```c
void print_msg(char *user){
  char formatter[0x20];
  strncpy(formatter, user, 5);
  for (size_t i = 0; i < 5; i++) formatter[i] = tolower(formatter[i]);
  printf(strncmp(formatter, "admin", 5) == 0 ? "\nWelcome admin!\n\n" : "\nWelcome user!\n\n");  
}
```

It takes our input and converts it to lowercase. Then, it compares the first 5 bytes of the input with `"admin"`. So, either we give `ADMIN`, `Admin`, `admin` and so on, the program will print the message.

#### Question 4

```console
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉
◉                                                       ◉
◉  HINT: This is the buffer --> char name[0x20] = {0};  ◉
◉                                                       ◉
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉

[*] Question number 0x4:

What is the size of the 'name' buffer (in hex or decimal)?
```

As we can see from the image, the buffer is `0x20` or `32` bytes long.

#### Question 5

```console
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉
◉                                                        ◉
◉  HINT: Only functions inside 'main()' are called.      ◉
◉        Also, the functions these functions call.       ◉
◉                                                        ◉
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉

[*] Question number 0x5:

Which custom function is never called? (e.g. vuln())
```

Taking a look at the `C` code again:

```c
#include <stdio.h>

void under_construction(){
  printf("This is under development\n");
}

void print_msg(char *user){
  char formatter[0x20];
  strncpy(formatter, user, 5);
  for (size_t i = 0; i < 5; i++) formatter[i] = tolower(formatter[i]);
  printf(strncmp(formatter, "admin", 5) == 0 ? "\nWelcome admin!\n\n" : "\nWelcome user!\n\n");  
}

int main(int argc, char **argv){
  char name[0x20] = {0};
  unsigned long x, y;
  printf("Enter your name: ");
  scanf("%s", name);
  print_msg(name);
  return 0;
}
```

The only function never called is `under_construction()`.

```c
void under_construction(){
  printf("This is under development\n");
}
```

#### Question 6

```console
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉
◉                                                         ◉
◉  HINT: Which function reads the string from the stdin?  ◉
◉                                                         ◉
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉

[*] Question number 0x6:

What is the name of the standard function that could trigger a Buffer Overflow? (e.g. fprintf())
```

The function that reads from the `stdin` in our program, is `scanf()`, thus it's the only one that could trigger a Buffer Overflow.

#### Question 7

```console
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉
◉                                                         ◉
◉  HINT: A Segmentation Fault occurs when the return      ◉
◉        address is overwritten with an invalid address.  ◉
◉                                                         ◉
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉

[*] Question number 0x7:

Insert 30, then 39, then 40 'A's in the program and see the output.

After how many bytes a Segmentation Fault occurs (in hex or decimal)?
```

After entering 40 `"A"`s, we that the program stops with a `Segmentation Fault` error. If we enter 39 `"A"`s, it does not produce this error.

```console 
challenge git:main ❯ ./main                                                                                   
Enter your name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Welcome user!

[1]    56606 segmentation fault (core dumped)  ./main
```

```console
challenge git:main ❯ ./main                                                                                   
Enter your name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 

Welcome user!

challenge git:main ❯
```

#### Question 8

```console
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉
◉                                                                    ◉
◉  HINT: Run 'gdb ./main' to open the binary in the debugger, then   ◉
◉        run 'p <function_name>' to see the address of a function.   ◉
◉                                                                    ◉
◉        e.g. pwndbg> p main                                         ◉
◉             $2 = {<text variable, no debug info>} 0x401294 <main>  ◉
◉                                                                    ◉
◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉◉

[*] Question number 0x8:

What is the address of 'under_construction()' in hex? (e.g. 0x401337)
```

We once again open the debugger and follow the instructions to get the address of `under_construction()`.

```gdb
pwndbg> p under_construction 
$1 = {<text variable, no debug info>} 0x4011d6 <under_construction>
```

We see that the address of `under_construction()` is `0x4011d6`. This was the last question and after that we get the flag.

```console
[*] Question number 0x8:

What is the address of 'under_construction()' in hex? (e.g. 0x401337)

>> 0x4011d6

♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠
♠                   ♠
♠      Correct      ♠
♠                   ♠
♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠ ♠

Great job! It's high time you solved your first challenge! Here is the flag!

HTB{f4k3_fl4g_f0r_writ3up}
```

# Solution

```python
#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.log_level = 'critical'

fname = './main' 

LOCAL = False

os.system('clear')

if LOCAL:
  print('Running solver locally..\n')
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP} {PORT}\n')

e   = ELF(fname)

[r.sendlineafter('>> ', i) for i in ['64-bit', 'nx', 'admin', '0x20', 'under_construction', 'scanf', '0x28', str(hex(e.sym.under_construction))]]

print(f'Flag --> {r.recvline_contains("HTB").decode()}\n')
```

```console
Running solver remotely at 0.0.0.0 1337

Flag --> HTB{f4k3_fl4g_f0r_writ3up}
```

