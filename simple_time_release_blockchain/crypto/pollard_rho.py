"""
Source: Handbook of Applied Cryptography chapter-3
        http://cacr.uwaterloo.ca/hac/about/chap3.pdf
"""
from Crypto.Util.number import *
from random import randint


def func_f(x_i, base, y, p):
    """
    x_(i+1) = func_f(x_i)
    """
    if x_i % 3 == 2:
        return (y*x_i) % p
    elif x_i % 3 == 0:
        return pow(x_i, 2, p)
    elif x_i % 3 == 1:
        return base*x_i % p
    else:
        print("[-] Something's wrong!")
        return -1


def func_g(a, n, p, x_i):
    """
    a_(i+1) = func_g(a_i, x_i)
    """
    if x_i % 3 == 2:
        return a
    elif x_i % 3 == 0:
        return 2*a % n
    elif x_i % 3 == 1:
        return (a + 1) % n
    else:
        print("[-] Something's wrong!")
        return -1


def func_h(b, n, p, x_i):
    """
    b_(i+1) = func_g(b_i, x_i)
    """
    if x_i % 3 == 2:
        return (b + 1) % n
    elif x_i % 3 == 0:
        return 2*b % n
    elif x_i % 3 == 1:
        return b
    else:
        print("[-] Something's wrong!")
        return -1


def pollard_eqs_solver(a1, b1, a2, b2, n):
    """
    If x_i == x_2i is True
    ==> (base^(a1))*(y^(b1)) = (base^(a2))*(y^(b2)) (mod p)
    ==> y^(b1 - b2) = base^(a2 - a1)                (mod p)
    ==> base^((b1 - b2)*x) = base^(a2 - a1)         (mod p)
    ==> (b1 - b2)*x = (a2 - a1)                     (mod n)
    r = (b1 - b2) % n
    if GCD(r, n) == 1 then,
    ==> x = (r^(-1))*(a2 - a1)                      (mod n)
    """
    r = (b1 - b2) % n
    if r == 0:
        print("[-] b1 = b2, returning -1")
        return -1
    else:
        """
        If `n` is not a prime number this algorithm will not be able to
        solve the DLP, because GCD(r, n) != 1 then and one will have to
        write an implementation to solve the equation:
            (b1 - b2)*x = (a2 - a1) (mod n)
        This equation will have multiple solutions out of which only one
        will be the actual solution
        """
        div = GCD(r, n)
        if div == 1:
            return (inverse(r, n) * (a2 - a1)) % n
        else:
            res_l = (b1 - b2) // div
            res_r = (a2 - a1) // div
            p1 = n // div
            return (inverse(res_l, p1) * res_r) % p1


def pollard_rho(base: int, y: int, p: int, n: int):
    """
    Refer to section 3.6.3 of Handbook of Applied Cryptography
    Computes `x` = a mod n for the DLP base**x % p == y
    in the Group G = {0, 1, 2, ..., n}
    given that order `n` is a prime number.

    Args:
        base: Generator of the group
        y: Result of base**x % p
        p: Group over which DLP is generated.
        n: Order of the group generated by `base`. Should be prime for this implementation

    Returns:

    """
    a_i = randint(0, n)
    b_i = randint(0, n)
    a_2i = a_i
    b_2i = b_i

    x_i = (pow(base, a_i, p) * pow(y, b_i, p)) % p
    x_2i = x_i

    i = 1
    while i <= n:
        # Single Step calculations
        a_i = func_g(a_i, n, p, x_i)
        b_i = func_h(b_i, n, p, x_i)
        x_i = func_f(x_i, base, y, p)

        # Double Step calculations
        xm_2i = func_f(x_2i, base, y, p)
        a_2i = func_g(func_g(a_2i, n, p, x_2i), n, p, xm_2i)
        b_2i = func_h(func_h(b_2i, n, p, x_2i), n, p, xm_2i)
        x_2i = func_f(xm_2i, base, y, p)

        if x_i == x_2i:
            return pollard_eqs_solver(a_i, b_i, a_2i, b_2i, n)
        else:
            i += 1
            continue
    return -1
