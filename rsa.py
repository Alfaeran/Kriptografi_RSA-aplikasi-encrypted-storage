import os

def is_prime(n, rounds=40):
    if n < 2:
        return False

    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)

    for p in small_primes:
        if n % p == 0:
            return n == p

    # n - 1 = d * 2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = 2 + int.from_bytes(os.urandom((n.bit_length() + 7) // 8), "big") % (n - 3)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(nbits):
    if nbits < 2:
        raise ValueError("nbits must be >= 2")

    nbytes = (nbits + 7) // 8
    excess_bits = nbytes * 8 - nbits

    while True:
        candidate = int.from_bytes(os.urandom(nbytes), "big")
        candidate &= (1 << nbits) - 1
        candidate |= 1 << (nbits - 1)
        candidate |= 1 

        if is_prime(candidate):
            return candidate

def generate_rsa_key_parts(nbits):
    """Like generate_rsa_key, but also exposes p, q and phi(n) for display."""
    if nbits < 4:
        raise ValueError("nbits must be >= 4")

    p = generate_prime(nbits // 2)
    q = generate_prime(nbits // 2)

    while p == q:
        q = generate_prime(nbits // 2)

    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = 65537
    d = pow(e, -1, phi_n)

    return {"p": p, "q": q, "n": n, "phi": phi_n, "e": e, "d": d}

def generate_rsa_key(nbits):
    k = generate_rsa_key_parts(nbits)
    return (k["n"], k["e"]), (k["n"], k["d"])

def encrypt(pubkey, plaintext):
    n, e = pubkey
    m = int(plaintext, 16)
    c = pow(m, e, n)
    ct_hex = hex(c)[2:]
    return ct_hex

def decrypt(privkey, ciphertext):
    n, d = privkey
    c = int(ciphertext, 16)
    p = pow(c, d, n)
    pt_hex = hex(p)[2:]
    return pt_hex
