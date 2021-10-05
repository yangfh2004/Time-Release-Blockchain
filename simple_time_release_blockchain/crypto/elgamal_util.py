"""
Math utility methods to support elgamal crypto system.
"""
import random


def gcd(a: int, b: int) -> int:
    """Computes the greatest common denominator of a and b.  assumes a > b.

    Args:
        a:
        b:

    Returns:
        Greatest common denominator
    """
    while b != 0:
        c = a % b
        a = b
        b = c
    # a is returned if b == 0
    return a


def mod_exp(base: int, exp: int, modulus: int) -> int:
    """Calling Python built-in method to implement fast modular exponentiation.

    Args:
        base:
        exp:
        modulus:

    Returns:

    """
    return pow(base, exp, modulus)


def solovay_strassen(num: int, i_confidence: int) -> bool:
    """ Solovay-strassen primality test.
    This function tests if num is prime.
    http://www-math.ucdenver.edu/~wcherowi/courses/m5410/ctcprime.html

    Args:
        num: input integer
        i_confidence:

    Returns:
        if pass the test
    """
    # ensure confidence of t
    for idx in range(i_confidence):
        # choose random a between 1 and n-2
        a = random.randint(1, num - 1)

        # if a is not relatively prime to n, n is composite
        if gcd(a, num) > 1:
            return False

        # declares n prime if jacobi(a, n) is congruent to a^((n-1)/2) mod n
        if not jacobi(a, num) % num == mod_exp(a, (num - 1) // 2, num):
            return False

    # if there have been t iterations without failure, num is believed to be prime
    return True


def jacobi(a: int, n: int) -> int:
    """Computes the jacobi symbol of a, n.

    Args:
        a:
        n:

    Returns:

    """
    if a == 0:
        if n == 1:
            return 1
        else:
            return 0
    # property 1 of the jacobi symbol
    elif a == -1:
        if n % 2 == 0:
            return 1
        else:
            return -1
    # if a == 1, jacobi symbol is equal to 1
    elif a == 1:
        return 1
    # property 4 of the jacobi symbol
    elif a == 2:
        if n % 8 == 1 or n % 8 == 7:
            return 1
        elif n % 8 == 3 or n % 8 == 5:
            return -1
        else:
            return 0
    # property of the jacobi symbol:
    # if a = b mod n, jacobi(a, n) = jacobi( b, n )
    elif a >= n:
        return jacobi(a % n, n)
    elif a % 2 == 0:
        return jacobi(2, n) * jacobi(a // 2, n)
    # law of quadratic reciprocity
    # if a is odd and a is co-prime to n
    else:
        if a % 4 == 3 and n % 4 == 3:
            return -1 * jacobi(n, a)
        else:
            return jacobi(n, a)


def find_primitive_root(p: int, seed: int) -> int:
    """Finds a primitive root for prime p.
    This function was implemented from the algorithm described here:
    http://modular.math.washington.edu/edu/2007/spring/ent/ent-html/node31.html

    Args:
        p:
        seed:

    Returns:
        A primitive root for prime p.
    """
    random.seed(seed)
    if p == 2:
        return 1
    # the prime divisors of p-1 are 2 and (p-1)/2 because
    # p = 2x + 1 where x is a prime
    p1 = 2
    p2 = (p - 1) // p1

    # test random g's until one is found that is a primitive root mod p
    while True:
        g = random.randint(2, p - 1)
        # g is a primitive root if for all prime factors of p-1, p[i]
        # g^((p-1)/p[i]) (mod p) is not congruent to 1
        if not (mod_exp(g, (p - 1) // p1, p) == 1):
            if not mod_exp(g, (p - 1) // p2, p) == 1:
                return g


def find_prime(bit_length: int, i_confidence: int, seed: int) -> int:
    """Find a prime number p for elgamal public key.

    Args:
        bit_length: number of binary bits for the prime number.
        i_confidence:
        seed: random generator seed

    Returns:
        A prime number with requested length of bits in binary.
    """
    random.seed(seed)
    # keep testing until one is found
    while True:
        # generate potential prime randomly
        p = random.randint(2 ** (bit_length - 2), 2 ** (bit_length - 1))
        # make sure it is odd
        while p % 2 == 0:
            p = random.randint(2 ** (bit_length - 2), 2 ** (bit_length - 1))

        # keep doing this if the solovay-strassen test fails
        while not solovay_strassen(p, i_confidence):
            p = random.randint(2 ** (bit_length - 2), 2 ** (bit_length - 1))
            while p % 2 == 0:
                p = random.randint(2 ** (bit_length - 2), 2 ** (bit_length - 1))

        # if p is prime compute p = 2*p + 1
        # if p is prime, we have succeeded; else, start over
        p = p * 2 + 1
        if solovay_strassen(p, i_confidence):
            return p

