![img](../../assets/banner.png)

<img src='../../assets/htb.png' style='zoom: 80%;' align=left /> <font 
size='6'>Symbols</font>

28<sup>th</sup> 2022 / Document No. D22.102.16

Prepared By: `aris`

Challenge Author(s): `aris`

Difficulty: <font color=green>Easy</font>

Classification: Official

# Synopsis

- This challenges introduces the player to the concept of Legendre Symbol. The task is to test whether the encrypted values $g^r$ are quadratic residues or not. If it is a quadratic residue then we know that the corresponding flag bit is $0$, otherwise it is $1$.

## Description

- The exam season is coming up, and you have to study the encryption used in malwares. The class structure involves the professors providing you with an encryption function, and your task is to find a way to decrypt the data without knowing the key. Practicing this will lead you to becoming proficient in cryptography, making data recovery by humans nearly impossible.

## Skills Required

- Basic knowledge of SageMath.
- Know how to check whether a prime or a generator can make DLP easier to solve.
- Basic number theory knowledge.

## Skills Learned

- Learn about the Legendre symbol and quadratic residues.

# Enumeration

## Analyzing the source code

In this challenge we are provided with two files:

- `source.py` : This is the main script that encrypts the flag and writes the data to the output file.
- `output.txt` : This is the output file that contains the data that we have to use to solve this challenge.

The flow of the main function is very easy to follow:

```python
def main():
		flag = int.from_bytes(FLAG, 'big')
    encrypted_flag = encrypt(flag)

    with open('output.txt', 'w') as f:
        f.write(str(encrypted_flag))
```

The function `encrypt` is called that encrypts the flag and then the ciphertext is outputted to `output.txt`. Let us take a closer look at the `encrypt` function.

```python
p = 307163712384204009961137975465657319439
g = 1337

def encrypt(m):
    bits = bin(m)[2:]
    encrypted = []

    for b in bits:
        r = (randint(2, p) << 1) + int(b)
        encrypted.append(pow(g, r, p))

    return encrypted
```

The flow of the `encrypt` function can be summarized as:

1. The message is converted into bits.
2. There is a loop iterating the bits of the message.
3. In each iteration, a random number $r$ is uniformly selected in the range $[2,\ p]$.
4. The current bit of the message, say $b$, is appended in the end of $r$, therefore making it an even number if $b = 0$, else odd.

The encrypted bit is computed as the result of the modular exponentiation $g^r \pmod p$.

As the flag is encrypted bit-by-bit, our goal is to recover the bits given the encrypted values and since $b$ is hidden in $r$, it is enough to determine whether $r$ is even or odd. If it is even, then the current bit of the flag is $0$, else it is a $1$.

Let us first write a function that loads the encrypted values from `output.txt`.

```python
def load_values():
		with open('output.txt') as f:
				encrypted_flag = eval(f.read())
		return encrypted_flag
```

# Solution

## Finding the vulnerability

First thing that comes to mind is solving the discrete logarithm problem in order to recover the unknown exponent $r$. Let us inspect the given $p$ and $g$ values.

$p$ is a 128-bit prime number which makes it almost infeasible to solve the discrete logarithm problem efficiently. However, knowing some attacks on the DLP, such as the Pohlig-Hellman attack, we can inspect the order of the prime and see if it contains small enough factors. The following code snippets will be written using SageMath.

```python
p = 307163712384204009961137975465657319439
print(factor(p-1))
```

```text
2 * 5923 * 1478672857 * 17535819988380789524657429
```

We can see that the size of the factors do not enable us to apply the PH attack. Our last opportunity is to verify that $g$ is a generator of $GF(p)$. Hopefully, it has small order.

```python
p = 307163712384204009961137975465657319439
g = 1337
F = GF(p)
print(F(g).multiplicative_order())
```

```text
307163712384204009961137975465657319438
```

Sadly, $g$ is a generator of $GF(p)$ so we can probably rule out the DLP approach and do some maths.

<h3>Legendre symbol</h3>

This challenge aims at introducing the player to the concept of the Legendre Symbol and its significance in asymmetric cryptography.

Let $p > 2$ a prime number and $a$ an element in $[0,\ p-1]$. Legendre symbol is a function of $a$ and $p$ is a function that takes three values in total, $-1, 0, 1$. The values are assigned according to the following:

- $-1$ if $a$ is not a perfect square modulo $p$.
- $1$ if $a$ is a perfect square modulo $p$.
- $0$ if $a = 0 \pmod p$.

Perfect square means that $a$ can be written as $a \equiv x^2 \pmod p$ for some integer $x$. We call the numbers that are congruent to a perfect square as **quadratic residues**, otherwise **quadratic nonresidues**. More specifically, the legendre symbol can be computed as:
$$
\begin{pmatrix}
\dfrac{a}{p}
\end{pmatrix}
= a^{\frac{p-1}{2}} \pmod p
$$
But how is this useful for us? It turns out that this gives us some important information for this challenge. We know $g$ is a generator, therefore there should not exist any value $x$ other than $p-1$ such that  $g^x \equiv 1 \pmod p$. This implies that the legendre symbol of generators is always $-1$. Namely:
$$
\begin{pmatrix}
\dfrac{g}{p}
\end{pmatrix}=g^{\frac{p-1}{2}} = -1 \pmod p
$$
We can rely on this property and notice that if $g$ is quadratic nonresidue then we know the even powers of $g$ are quadratic residues and the odd powers are quadratic nonresidues. Let us see why. Let a random odd number $r$. Our goal is to determine whether $g^r$ is a quadratic residue or not.
$$
\begin{pmatrix}
\dfrac{g^r}{p}
\end{pmatrix}=g^{r\frac{p-1}{2}} = (g^{\frac{p-1}{2}})^r = (-1)^r = -1 \pmod p
$$
Therefore we found that when $r$ is odd, $g^r$ is a quadratic nonresidue. If $r$ was even, $(-1)^r$ would be equal to $1$ which makes it a quadratic residue.

Back to our challenge, remember that our task is to determine whether the exponent $r$ is odd or even. The legendre symbol can give us this information. The idea is to compute the legendre symbol of each of the encrypted values $g^r$ and test whether the result is $-1$ or $1$.

If the result is $1$ then $g^r$ is a quadratic residue and $r$ is even, so $b$ must be $0$.

Let us write a function that checks whether a value is a quadratic residue or not.

```python
def is_quadratic_residue(a, p):
		return pow(a, (p-1)//2, p) == 1
```

## Exploitation

By implementing the idea above, we can recover the flag bit-by-bit.

```python
from Crypto.Util.number import long_to_bytes

def recover_flag_bits(encrypted_flag):
    flag = ''
    for e in encrypted_flag:
        if is_quadratic_residue(e, p):
        		flag += '0'
        else:
            flag += '1'
		flag = long_to_bytes(int(flag, 2))
    
		return flag
```

### Getting the flag

A final summary of all that was said above:

1. Notice that our task is to find the LSB of $r$; in other words, determine whether $r$ is odd or even.
2. Inspect $p$ and $g$ and test whethre solving DLP is feasible in a logical amount of time.
3. This inspection fails so we think of Legendre symbol.
4. We can determine the flag bits one-by-one by checking whether the encrypted values are quadratic residues or not.

This recap can be represented by code with the `pwn()` function:

```python
def pwn():
		encrypted_flag = load_values()
    flag = recover_flag_bits(encrypted_flag)
    print(flag)

if __name__ == '__main__':
  	pwn()
```
