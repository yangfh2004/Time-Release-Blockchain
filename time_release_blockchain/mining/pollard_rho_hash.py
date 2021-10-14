"""
Pollard rho based hash mining algorithm.
"""
from time_release_blockchain.miner import Block
from time_release_blockchain.crypto.elgamal import PublicKey
from time_release_blockchain.crypto.pollard_rho import func_g, func_h, pollard_eqs_solver
from random import randint


def header_hash(block: Block, pubkey: PublicKey, nonce: int) -> int:
    block.nonce = nonce
    hash_val = int.from_bytes(block.hash_header(), byteorder='little', signed=True) % pubkey.p
    return hash_val


def func_f(hash_i, x_i, base, y, p):
    """
    x_(i+1) = func_f(hash(x_i))
    """
    if hash_i % 3 == 2:
        return (y*x_i) % p
    elif hash_i % 3 == 0:
        return pow(x_i, 2, p)
    elif hash_i % 3 == 1:
        return base*x_i % p
    else:
        print("[-] Something's wrong!")
        return -1


def pollard_rho_hash(block: Block) -> tuple[int, int]:
    """
    Refer to section 3.6.3 of Handbook of Applied Cryptography
    Computes `x` = a mod n for the DLP base**x % p == y
    in the Group G = {0, 1, 2, ..., n}
    given that order `n` is a prime number.

    Args:
        block: current block for hashing

    Returns:
        nonce and paired private key
    """
    pubkey = block.public_key
    n = (pubkey.p - 1) // 2

    a_i = randint(0, n)
    b_i = randint(0, n)
    a_2i = a_i
    b_2i = b_i

    x_i = (pow(pubkey.g, a_i, pubkey.p) * pow(pubkey.h, b_i, pubkey.p)) % pubkey.p
    x_2i = x_i

    i = 1
    while i <= n:
        # Single Step calculations
        hash_1i = header_hash(block, pubkey, x_i)
        a_i = func_g(a_i, n, pubkey.p, hash_1i)
        b_i = func_h(b_i, n,  pubkey.p, hash_1i)
        x_i = func_f(hash_1i, x_i, pubkey.g, pubkey.h, pubkey.p)

        # Double Step calculations
        hash_2mi = header_hash(block, pubkey, x_2i)
        a_2i = func_g(a_2i, n, pubkey.p, hash_2mi)
        b_2i = func_h(b_2i, n, pubkey.p, hash_2mi)
        x_2mi = func_f(hash_2mi, x_2i, pubkey.g, pubkey.h, pubkey.p)
        hash_2i = header_hash(block, pubkey, x_2mi)
        a_2i = func_g(a_2i, n, pubkey.p, hash_2i)
        b_2i = func_h(b_2i, n, pubkey.p, hash_2i)
        x_2i = func_f(hash_2i, x_2mi, pubkey.g, pubkey.h, pubkey.p)

        if x_i == x_2i:
            # print("left side = ", (pow(pubkey.g, a_i, pubkey.p) * pow(pubkey.h, b_i, pubkey.p)) % pubkey.p)
            # print("right side = ", (pow(pubkey.g, a_2i, pubkey.p) * pow(pubkey.h, b_2i, pubkey.p)) % pubkey.p)
            return x_2mi, pollard_eqs_solver(a_i, b_i, a_2i, b_2i, n)
        else:
            i += 1
            continue
    return -1, -1
