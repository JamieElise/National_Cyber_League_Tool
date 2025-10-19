import math

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def trial_factor(n):
    # quick/naive factor for small RSA labs
    if n % 2 == 0:
        return 2, n // 2
    f = 3
    while f * f <= n:
        if n % f == 0:
            return f, n // f
        f += 2
    return None, None  # not found

def modinv(a, m):
    # Python 3.8+ supports modular inverse via pow
    a %= m
    inv = pow(a, -1, m)  # raises ValueError if no inverse
    return inv

def decrypt_numbers(n, e, c_list, p=None, q=None):
    if p is None or q is None:
        # factor n (for small lab numbers)
        pf, qf = trial_factor(n)
        if not pf:
            raise ValueError("Couldn't factor n quickly; please provide p and q.")
        p, q = (pf, qf) if pf <= qf else (qf, pf)

    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError("e and phi(n) are not coprime; cannot compute d.")
    d = modinv(e, phi)

    m_vals = [pow(c, d, n) for c in c_list]
    try:
        plaintext = "".join(chr(m) for m in m_vals)
    except ValueError:
        # if any m is not a valid Unicode code point
        plaintext = None
    return p, q, phi, d, m_vals, plaintext

# --- Interactive use ---
def main():
    n = int(input("Enter n (modulus): ").strip())
    e = int(input("Enter e (public exponent): ").strip())

    pq_known = input("Do you know p and q? [y/N]: ").strip().lower() == "y"
    p = q = None
    if pq_known:
        p = int(input("Enter p (smaller prime): ").strip())
        q = int(input("Enter q (larger prime): ").strip())

    c_str = input("Enter ciphertext integers (space-separated): ").strip()
    c_list = [int(x) for x in c_str.split()] if c_str else []

    p, q, phi, d, m_vals, plaintext = decrypt_numbers(n, e, c_list, p, q)

    print(f"\nFactorization: p = {p}, q = {q}")
    print(f"phi(n) = {phi}")
    print(f"d (mod inverse of e mod phi) = {d}")
    print("m values:", m_vals)
    if plaintext is not None:
        print("plaintext:", plaintext)
    else:
        print("plaintext: (some values not valid code points)")

if __name__ == "__main__":
    main()

