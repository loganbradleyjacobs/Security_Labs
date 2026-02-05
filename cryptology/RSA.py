import math
from .ciph_utils import Utils, LOWER

def find_n(p: int, q: int) -> int:
    n = p * q
    return n

def find_totient(p: int, q:int) -> int:
    return (p-1) * (q-1)

def find_e_any(phi_n: int) -> int:
    for e in range(2, phi_n):
        if math.gcd(e, phi_n) == 1:
            return e
    raise ValueError("No valid e found.")

def find_e_from_d(phi_n: int, d: int) -> int:
    g, x, _ = ext_gcd(d, phi_n)
    if g != 1:
        raise ValueError("d and phi_n are not relatively prime.")
    return x % phi_n

def ext_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = ext_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y

def find_d(e: int, phi_n: int) -> int:
    g, x, _ = ext_gcd(e, phi_n)
    if g != 1:
        raise ValueError("e and phi_n are not relatively prime.")
    return x % phi_n

def encrypt(M_ord: list[int], key: int, n: int) -> str:
    return [pow(m, key, n) for m in M_ord]

def main() -> None:
    print("2a) --------------------")
    p = 7
    q = 11
    n = find_n(p, q)
    phi_n = find_totient(p, q)
    e = find_e_any(phi_n)
    d = find_d(e, phi_n)
    print(f"Valid d: {d}")
    print(f"Another valid d: {d + phi_n}")
    print(f"To find more valid d values: d + (i * phi_n) = ({d} + (i * {phi_n}))")

    print("2b) --------------------")
    p = 13
    q = 31
    d = 7
    n = find_n(p, q)
    phi_n = find_totient(p, q)
    e = find_e_from_d(phi_n, d)
    print(f"The value of e is: {e}")

    print("2c) --------------------")
    p = 5
    q = 11
    d = 27
    n = find_n(p, q)
    phi_n = find_totient(p, q)
    e = find_e_from_d(phi_n, d)
    print(f"e: {e}")
    M = "abc"
    M_ord = Utils.ord_str(M, LOWER, start_index=1) # converts "abc" -> [1, 2, 3]
    C = encrypt(M_ord, e, n)
    decrypted_C = Utils.chr_str(C, LOWER, start_index=1)
    print(f"Encrypted Message: {decrypted_C}")



if __name__ == "__main__":
    main()