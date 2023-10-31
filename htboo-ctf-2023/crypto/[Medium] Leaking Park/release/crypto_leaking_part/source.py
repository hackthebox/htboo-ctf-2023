from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime
from sympy import nextprime
import math
from secret import FLAG

MAX = 0x100

def factors():
    return [getPrime(int(math.log2(MAX))) for i in range(int(math.log2(MAX)))]

class RSA:
    def __init__(self):
        p, q, self.leak = self.craft_primes()
        self.n = p * q
        self.e = 0x10001

    def craft_primes(self):
        numb = 1
        count, p, q = 0, 0, 0

        for i in factors():
            count += 1
            numb *= math.prod(range(1, i))

            if count == 4:
                p = nextprime(numb)
            if count == 8:
                q = nextprime(numb//p)

        return p, q, numb
    
    def encrypt(self, m):
        return pow(m, self.e, self.n)

def main():
    rsa = RSA()

    ct = rsa.encrypt(bytes_to_long(FLAG))

    with open('output.txt', 'w') as f:
        f.write(f'{hex(rsa.leak)[2:]}\n{hex(rsa.e)[2:]}\n{hex(ct)[2:]}')

if __name__ == "__main__":
    main()
