# My personal implementation of Paillier encryption
# 1. Library declaration, constants and helper functions

import math
import secrets

SMALL_TEST = 64
MEDIUM_TEST = 128
LARGE_TEST = 256
NIST_MINIMUM = 1024

# --- key generation ---
# generate a random value between BIT_SIZE/2 and BITSIZE/2 - 1 for p and q
def random_odd_int(bits):
    """
    Generate a random odd integer with exactly `bits` bits.
    Ensures:
      - highest bit set  -> exact bit length
      - lowest bit set   -> odd number
    """
    x = secrets.randbits(bits)
    x |= (1 << (bits - 1))   # force top bit
    x |= 1                   # force odd
    return x

# true if number is prime, false if not.
def MillerRabin_primality(n):
    rounds = 40

    if n < 2:
        return False

    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    # write n - 1 = d * 2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        skip = False
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                skip = True
                break
        if skip:
            continue
        return False

    return True

def prime(bits: int) -> int:
    """
    Generate a prime of exact bit length.
    """
    while True:
        prime = random_odd_int(bits)
        if MillerRabin_primality(prime):
            return prime

# 2. Derive parameters for Paillier

# make sure p and q are two distinct primes while having the same bit size
def generate_pq(bits):
    while True:
        p = prime(bits)
        q = prime(bits)
        if p != q:
            return p, q

# random value, r picked from range [1, n]
def generate_r(n):
  return secrets.randbelow(n) + 1

# generator, g(n) = n + 1 to simplify solving of mu
def generate_g(n):
  return n + 1

# lambda / Carmichael function, λ(n) = lcm(p - 1, q - 1)
def lam(p, q):
  return math.lcm(p - 1, q - 1)

# L function, L(x) = (x - 1) / n
def L(x, n):
  return (x - 1) // n

# mu, μ = ( L(g^λ mod n²) )^(-1) mod n
def mu(g_val, lam_val, n):
  n_sq = n * n
  u = pow(g_val, lam_val, n_sq)
  l_val = L(u, n)

  return pow(l_val, -1, n)

def generate_Paillier_parameters(bits):
  p, q = generate_pq(bits)
  n = p * q
  n_sq = n * n
  g = generate_g(n)
  lam_val = lam(p, q)
  mu_val = mu(g, lam_val, n)
  return p, q, n, n_sq, g, lam_val, mu_val

# 3. Package the messages if they get too big for n's capacity (TODO)

def pack(value):
  print("TODO: 'pack' function")

# 4. Encryption, decryption and homomorphic operations

def encrypt(m, g, n, n_sq, r):
  return (pow(g, m, n_sq) * pow(r, n, n_sq)) % n_sq

def decrypt(m_encrypted, lam_val, mu_val, n, n_sq):
    x = pow(m_encrypted, lam_val, n_sq)
    m = (L(x, n) * mu_val) % n

    # provision for when we use negative value messages
    if m > n // 2:
        m = m - n
    return m

def homomorphic_sum(e_m1, e_m2, n_sq):
    return (e_m1 * e_m2) % n_sq

# helper to sum all messages at once.
def homomorphic_sum_all(*args, n_sq):
    result = 1
    for arg in args:
        result = homomorphic_sum(result, arg, n_sq)
    return result

def homomorphic_scalar_multiple(c, k, n_sq):
    return pow(c, k, n_sq)

# 5. Main program

m1 = 3000
m2 = 334
m3 = -5
s = 7

p, q, n, n_sq, g, lam_val, mu_val = generate_Paillier_parameters(SMALL_TEST)

#5.1 control
control_solution = (m1 + m2 + m3) * s

#5.2 Paillier
value = (m1 + m2 + m3) * s
if value > n:
    pack(value)

e_m1 = encrypt(m1, g, n, n_sq, generate_r(n))
e_m2 = encrypt(m2, g, n, n_sq, generate_r(n))
e_m3 = encrypt(m3, g, n, n_sq, generate_r(n))
e_sum = homomorphic_sum_all(e_m1, e_m2, e_m3, n_sq=n_sq)
e_solution = homomorphic_scalar_multiple(e_sum, s, n_sq)
paillier_solution = decrypt(e_solution, lam_val, mu_val, n, n_sq)

#5.3 Validate results
print("control_solution =", control_solution)
print("paillier_solution =", paillier_solution)
assert control_solution == paillier_solution
