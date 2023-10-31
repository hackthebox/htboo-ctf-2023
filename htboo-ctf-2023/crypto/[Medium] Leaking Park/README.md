﻿# Leaking Part Writeup

Author : `0xD10`

### Description 
- For your final exercise, you aimed to create the spookiest encryption algorithm that bridges the human and ghost worlds. You chose RSA with a unique twist on prime generation. However, as a friend of the humans, your objective is to create something with a backdoor for decryption. You believe you've designed a solution that will deceive the Ghost Academy committee. Can you create a proof of concept to share with the humans?

## Understanding the code
1.  We start by examine the factor function. Understanding it we conclude that it makes an array of 8 random primes within the range(0,256). `MAX = 0x100 = 256`  ||  `math.log2(MAX) = 8` 
```py 
MAX = 0x100

def factors():
    return [getPrime(int(math.log2(MAX))) for i in range(int(math.log2(MAX)))]
```
2.  Then the craft functions takes the array and performs a multiplication within the range of the prime.
Example: Let's say we have an array `primes = [2,5,7..]`
- `numb0 = numb0 * 2`
- `numb1 = numb0 * 2 * 3 * 4`
- `numb2 = numb1 * 2 * 3 * 4 * 5 * 6`
- `numb(n) = numb(n-1) * 2*...*(prime-1)`
So the basic idea to this is that we create a big enough "leak" which contains the factors of p and q
```py
numb = 1
count = 0
a,b = 0,0
for i in factors():
        count+=1
        for j in range(2,i):
            numb*=j
        if count == 4:
            a = nextprime(numb)
        if count == 8:
            b = nextprime(numb//a)
```

Take a look at the example that we did earlier : 
- `numb0 = numb0 * 2`
- `numb1 = numb0 * 2 * 3 * 4`
- `numb2 = numb1 * 2 * 3 * 4 * 5 * 6`

 `numb = numb2`
The number 2 appears three times it is like we have 2 in the power of 3 `pow(2,3)`
What if we remove all of the 2 in the numb?
`numb // pow(2,3)` removes all the 2 in the numb, but we also want to detect the factor
We can find the factor by doing this:
```py
factors = []
temp = numb
power = 3
start = 2
for in range(start,256):
	x = pow(start,power)
	if temp % x != 0:
		start = i
		power -= 1
		print("Found!")
		factors.append(i)
		break
	else:
		temp = temp // x
```
This only founds one factor and in our case we have to find 8 primes!
Simply add a While loop and decrease the power variable by one.
```py
factors = []
start = 2
power = 8

while power>0:
    for i in range(start,MAX):
        x = pow(i,power)
        if temp_leak % x != 0:
            start = i
            power -= 1
            print("Found!")
            factors.append(i)
            break
        else:
            temp_leak = temp_leak // x

print("factors = ",factors)
```
The result from the above code will be something like this `factors = [2,5,7,...]` it would be in ascending order. We have to consider that the factors of the prime are in random order, and from the 8 factors we have found, we need all the combinations in 4 sets and we can do that with this library `itertools` and this command
`x = combinations(array_of_values, combination_range)`
```py
try_p = combinations(factors,4)
p = []
for i in try_p:
    total = 1
    for j in i:
        for z in range(2,j):
            total*=z
    p.append(nextprime(total))
    print("Found ",len(p)," possible p") 
```
After we calculate all of the possible results of p we need to test them. Using the `leak` we can test much more faster whether p is the correct one. `q1 = nextprime(leak//p1)` reminds us this command from the source file  `b = nextprime(numb//a)`
```py
count = 0
for p1 in p:
    q1 = nextprime(leak//p1)
    n = p1*q1
    d = inverse(e,(p1-1)*(q1-1))
    res = long_to_bytes(pow(ct,d,n))
    if b'HTB{' in res:
        print("Found the flag : ",res)
        exit(1)
    else:
        count+=1
        print(f"Tried {count} p")
```
Finally after a lot of minutes our program can calculate the factors that produced the p and q, finding the flag
## Solution
```py
from Crypto.Util.number import *
from itertools import combinations
from sympy import nextprime

leak = #{value from output.txt}
e = #{value from output.txt}
ct = #{value from output.txt}

MAX = 256
temp_leak = leak

factors = []
start = 2
power = 8

while power>0:
    for i in range(start,MAX):
        x = pow(i,power)
        if temp_leak % x != 0:
            start = i
            power -= 1
            print("Found!")
            factors.append(i)
            break
        else:
            temp_leak = temp_leak // x

print("factors = ",factors)


try_p = combinations(factors,4)
p = []
for i in try_p:
    total = 1
    for j in i:
        for z in range(2,j):
            total*=z
    p.append(nextprime(total))
    print("Found ",len(p)," possible p")   

count = 0
for p1 in p:
    q1 = nextprime(leak//p1)
    n = p1*q1
    d = inverse(e,(p1-1)*(q1-1))
    res = long_to_bytes(pow(ct,d,n))
    if b'HTB{' in res:
        print("Found the flag : ",res)
        exit(1)
    else:
        count+=1
        print(f"Tried {count} p")
```
