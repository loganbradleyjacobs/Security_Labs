# Logan Jacobs
# CSC-348 Computer Security
# 2/5/26

import math
from typing import List, Tuple
from ..ciph_utils import Utils, LOWER


def find_n(p: int, q: int) -> int:
    """
    Compute the RSA modulus n = p * q.

    Args:
        p (int): Prime number.
        q (int): Prime number.

    Returns:
        int: RSA modulus n.

    Raises:
        ValueError: If p or q is not a positive integer.
    """
    if p <= 1 or q <= 1:
        raise ValueError("p and q must be integers greater than 1.")
    return p * q


def find_totient(p: int, q: int) -> int:
    """
    Compute Euler's totient φ(n) for RSA, where n = p * q.

    Args:
        p (int): Prime number.
        q (int): Prime number.

    Returns:
        int: φ(n) = (p - 1)(q - 1).

    Raises:
        ValueError: If p or q is not greater than 1.
    """
    if p <= 1 or q <= 1:
        raise ValueError("p and q must be integers greater than 1.")
    return (p - 1) * (q - 1)


def find_e_any(phi_n: int) -> int:
    """
    Find any valid public exponent e such that gcd(e, φ(n)) = 1.

    Args:
        phi_n (int): Euler's totient φ(n).

    Returns:
        int: A valid public exponent e.

    Raises:
        ValueError: If no valid e exists.
    """
    if phi_n <= 2:
        raise ValueError("phi_n must be greater than 2.")

    for e in range(2, phi_n):
        if math.gcd(e, phi_n) == 1:
            return e

    raise ValueError("No valid public exponent e found.")


def find_e_from_d(phi_n: int, d: int) -> int:
    """
    Compute the public exponent e given the private exponent d.

    This solves:
        e ≡ d⁻¹ (mod φ(n))

    Args:
        phi_n (int): Euler's totient φ(n).
        d (int): Private exponent.

    Returns:
        int: Corresponding public exponent e.

    Raises:
        ValueError: If d and φ(n) are not relatively prime.
    """
    if phi_n <= 0 or d <= 0:
        raise ValueError("phi_n and d must be positive integers.")

    g, x, _ = ext_gcd(d, phi_n)
    if g != 1:
        raise ValueError("d and phi_n are not relatively prime; inverse does not exist.")

    return x % phi_n


def ext_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean Algorithm.

    Computes gcd(a, b) and integers x, y such that:
        ax + by = gcd(a, b)

    Args:
        a (int): First integer.
        b (int): Second integer.

    Returns:
        Tuple[int, int, int]: (gcd, x, y)
    """
    if b == 0:
        return a, 1, 0

    g, x1, y1 = ext_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y


def find_d(e: int, phi_n: int) -> int:
    """
    Compute the private exponent d given public exponent e.

    This solves:
        d ≡ e⁻¹ (mod φ(n))

    Args:
        e (int): Public exponent.
        phi_n (int): Euler's totient φ(n).

    Returns:
        int: Private exponent d.

    Raises:
        ValueError: If e and φ(n) are not relatively prime.
    """
    if e <= 0 or phi_n <= 0:
        raise ValueError("e and phi_n must be positive integers.")

    g, x, _ = ext_gcd(e, phi_n)
    if g != 1:
        raise ValueError("e and phi_n are not relatively prime; inverse does not exist.")

    return x % phi_n


def encrypt(M_ord: List[int], key: int, n: int) -> List[int]:
    """
    Encrypt a message using RSA modular exponentiation.

    Args:
        M_ord (List[int]): Message encoded as integers.
        key (int): RSA exponent (e or d).
        n (int): RSA modulus.

    Returns:
        List[int]: Encrypted message as integers.

    Raises:
        ValueError: If message values are outside valid range.
    """
    if n <= 0 or key <= 0:
        raise ValueError("RSA key and modulus must be positive.")

    for m in M_ord:
        if not (0 <= m < n):
            raise ValueError(f"Message value {m} is outside valid range [0, n).")

    return [pow(m, key, n) for m in M_ord]


def main() -> None:
    """
    Demonstrates RSA key generation and encryption for assignment problems.
    """
    try:
        print("2a) --------------------")
        p = 7
        q = 11
        n = find_n(p, q)
        phi_n = find_totient(p, q)
        e = find_e_any(phi_n)
        d = find_d(e, phi_n)

        print(f"Valid d: {d}")
        print(f"Another valid d: {d + phi_n}")
        print(f"General form: d + (i * phi_n) = ({d} + (i * {phi_n}))")

        print("\n2b) --------------------")
        p = 13
        q = 31
        d = 7
        n = find_n(p, q)
        phi_n = find_totient(p, q)
        e = find_e_from_d(phi_n, d)

        print(f"The value of e is: {e}")

        print("\n2c) --------------------")
        p = 5
        q = 11
        d = 27
        n = find_n(p, q)
        phi_n = find_totient(p, q)
        e = find_e_from_d(phi_n, d)

        print(f"e: {e}")

        M = "abc"
        M_ord = Utils.ord_str(M, LOWER, start_index=1)  # "abc" -> [1, 2, 3]
        C = encrypt(M_ord, e, n)
        decrypted_C = Utils.chr_str(C, LOWER, start_index=1)

        print(f"Encrypted Message: {decrypted_C}")

    except ValueError as err:
        print(f"[ERROR] {err}")


if __name__ == "__main__":
    main()
