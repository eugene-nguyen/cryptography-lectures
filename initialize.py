# creates file "keys.txt" which contains one person's public and private RSA keys.
# 1. The two parties have each other’s RSA public key. Each of them holds his/her own RSA private key.

import math
import random

# checks if input number "n" is a prime.
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, n // 2 + 1):
        if n % i == 0:
            return False
    return True

# generates a random prime number "n" from range "min" to "max". min is assumed lower than max.
def generate_prime(min, max):
    print("generating prime")
    n = random.randint(min, max)
    while not is_prime(n):
        n = random.randint(min, max)
    return n

def mod_inverse(e, phi):
    print ("finding mod inverse")
    for d in range(3, phi):
        if (d * e) % phi == 1:
            return d
    return -1 # invalid value

# generating new keys. returns 3 values: e, n, and d
def generate_keys():
    # select random high primes p and q, and their totient (totient of n)
    p = generate_prime(10000, 50000)
    q = generate_prime(10000, 50000)
    while (q == p):
        q = generate_prime(10000, 50000)

    n = p * q
    totient = (p - 1) * (q - 1)

    # finding e: 1 < e < totient and gcd(e, totient) = 1, randomly going through numbers from 2 to totient - 1 until one is valid.
    e = random.randint(3, totient - 1)
    while math.gcd(e, totient) != 1:
        e = random.randint(2, totient - 1)
    
    d = mod_inverse(e, totient)
    keys = []
    keys.append(e)
    keys.append(n)
    keys.append(d)
    return keys

# runs the generate_keys function then outputs a txt file of "keys.txt"
def main():
    keys = generate_keys()
    with open("pu_keys.txt", "w") as file:
        file.write(str(keys[0]) + "\n" + str(keys[1])) # txt file contains e and then n on different lines
        print("public keys generated in pu_keys.txt")

    with open("pr_keys.txt", "w") as file:
        file.write(str(keys[2]) + "\n" + str(keys[1])) # txt file contains d and then n on different lines
        print("private keys generated in pr_keys.txt")
    
main()