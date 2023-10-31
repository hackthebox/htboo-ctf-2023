![](https://github.com/hackthebox/writeup-templates/raw/master/challenge/assets/images/banner.png)

<img src="https://github.com/hackthebox/writeup-templates/raw/master/challenge/assets/images/htb.png" style="margin-left: 20px; zoom: 80%;" align=left/>
<font size="10">SpookyCheck</font>
6<sup>th</sup> 09 23 / Document No. D22.102.XX
Prepared By: clubby789
Challenge Author: clubby789
Difficulty: <font color=orange>Medium</font>
Classification: Official

# Synopsis

SpookyCheck is a Hard reversing challenge. Players will disassemble or decompile Python 3.11 bytecode in order to reverse the operations used by a flag checker.

## Skills Required
    - Python disassembly
## Skills Learned
    - Reconstructing disassembled Python without a decompiler

# Solution

If we run `strings` on the file, `check.pyc`, we are given this information.

`check.pyc: Byte-compiled Python module for CPython 3.11, timestamp-based, .py timestamp: Mon Sep  4 15:32:51 2023 UTC, .py size: 656 bytes`

If we run it, we're given a prompt:

```
$ python3 check.pyc
🎃 Welcome to SpookyCheck 🎃
🎃 Enter your password for spooky evaluation 🎃
👻 test
💀 Not spooky enough, please try again later 💀
```

## Analaysis

We can begin by checking the variables exposed by the `check` module when we import it.

```
>>> dir(check)
['CHECK', 'KEY', '__builtins__', '__cached__', '__doc__', '__file__', '__loader__', '__name__', '__package__', '__spec__', 'check', 'transform']
>>> check.CHECK, check.KEY, check.check, check.transform
(bytearray(b'\xe9\xef\xc0V\x8d\x8a\x05\xbe\x8ek\xd9yX\x8b\x89\xd3\x8c\xfa\xdexu\xbe\xdf1\xde\xb6\\'), b'SUP3RS3CR3TK3Y', <function check at 0x7ff269fcff60>, <function transform at 0x7ff269fcfec0>)
>>> 
```

## Disassembly

At time of writing, decompiler tools such as Uncompyle6 do not support Python 3.11. We'll begin by using Python's builtin `dis` module to disassemble the compiled code object.

### `check` function

```
Disassembly of check:
 10           0 RESUME                   0

 11           2 LOAD_GLOBAL              1 (NULL + transform)
             14 LOAD_FAST                0 (flag)
             16 PRECALL                  1
             20 CALL                     1
             30 LOAD_GLOBAL              2 (CHECK)
             42 COMPARE_OP               2 (==)
             48 RETURN_VALUE
```

With some referral to the [`dis` docs](https://docs.python.org/3/library/dis.html), we can identify that this function loads an argument named 'flag', calls the function `transform` on it, and compares the result to the `CHECK` global we saw earlier, a collection of random-looking bytes. 

This means that `transform` performs a number of byte operations on the 'flag' input, then compares it to the expected result.

### `transform` function

```
Disassembly of transform:
  4           0 RESUME                   0

  5           2 LOAD_CONST               1 (<code object <listcomp> at 0x7ff26a5c4880, file "check.py", line 5>)
              4 MAKE_FUNCTION            0

  7           6 LOAD_GLOBAL              1 (NULL + enumerate)
             18 LOAD_FAST                0 (flag)
             20 PRECALL                  1
             24 CALL                     1

  5          34 GET_ITER
             36 PRECALL                  0
             40 CALL                     0
             50 RETURN_VALUE
```

This function loads some bytecode (named 'listcomp', so likely the conents of a list comprehension). It passes the result of `enumerate(flag)` into the comprehension, so each iteration of the comprehension will be called on an `(index, byte)` tuple.

### `listcomp`

```
Disassembly of <code object <listcomp> at 0x7ff26a5c4880, file "check.py", line 5>:
  5           0 RESUME                   0
              2 BUILD_LIST               0
              4 LOAD_FAST                0 (.0)
        >>    6 FOR_ITER                54 (to 116)

  7           8 UNPACK_SEQUENCE          2
             12 STORE_FAST               1 (i)
             14 STORE_FAST               2 (f)

  6          16 LOAD_FAST                2 (f)
             18 LOAD_CONST               0 (24)
             20 BINARY_OP                0 (+)
             24 LOAD_CONST               1 (255)
             26 BINARY_OP                1 (&)
             30 LOAD_GLOBAL              0 (KEY)
             42 LOAD_FAST                1 (i)
             44 LOAD_GLOBAL              3 (NULL + len)
             56 LOAD_GLOBAL              0 (KEY)
             68 PRECALL                  1
             72 CALL                     1
             82 BINARY_OP                6 (%)
             86 BINARY_SUBSCR
             96 BINARY_OP               12 (^)
            100 LOAD_CONST               2 (74)
            102 BINARY_OP               10 (-)
            106 LOAD_CONST               1 (255)
            108 BINARY_OP                1 (&)

  5         112 LIST_APPEND              2
            114 JUMP_BACKWARD           55 (to 6)
        >>  116 RETURN_VALUE

```

The loop body is between '8' and '116'. We begin by storing our index and byte into two variables (`i`, `f`).

We then load `f` and the value `24` and add them together, before `&`ing the result with 255, keeping it in byte range.

We'll illustrate the Python stack at each step for the next few instructions:

```
             30 LOAD_GLOBAL              0 (KEY)         => [KEY]
             42 LOAD_FAST                1 (i)           => [i, KEY]
             44 LOAD_GLOBAL              3 (NULL + len)  => [len, i, KEY]
             56 LOAD_GLOBAL              0 (KEY)         => [KEY, len, i, KEY]
             68 PRECALL                  1
             72 CALL                     1               => [len(KEY), i, KEY]
             82 BINARY_OP                6 (%)           => [i%len(KEY), KEY]
             86 BINARY_SUBSCR                            => [KEY[i%len(KEY)]]
```

The result of this is to take the byte in `KEY` at index `i`, modulo the length of `KEY`.

This is then XOR'd against the previous value (`f+24 & 0xff`). Finally, we subtract 74 and once again `&` it with 255.

## Solving

We now know each stage of the flag transformation. From here, we could either
    - Attempt to reverse each step of the process, which could be difficult due to the wrapping behaviour of +/-
    - Brute force each character byte-by-byte to find the correct input
    - Use z3 to automatically solve

We'll use the third option, as it demonstrates an interesting technique.
We begin by importing z3, initialising our Solver and preparing symbolic variables for each character in the flag.
```py
from z3 import *
import check
s = Solver()
flag = [BitVec(f"flag_{i}", 8) for i in range(len(check.CHECK))]
```

We can then perform our transformations. However, we don't need to do this manually - z3 overloads operators on its symbolic variable types, so we can simply pass our symbolic flag to the transformation function to get a transformed symbolic input:
```py
trans = check.transform(flag)
for i in range(len(flag)):
    s.add(trans[i] == check.CHECK[i])
```

We're now ready to process our model and evaluate the flag from our input:
```py
print(s.check())
m = s.model()

print(''.join(chr(m[f].as_long()) for f in flag))
```
