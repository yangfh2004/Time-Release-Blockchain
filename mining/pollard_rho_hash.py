"""
Pollard rho based hash mining algorithm.
"""
from blockchain.block import Block
from crypto.elgamal import PrivateKey
from crypto.pollard_rho import func_g, func_h, pollard_eqs_solver
from random import randint
from typing import Optional
import time


class PRSolution:
    """Solution from pollard rho method."""
    def __init__(self, a1, a2, b1, b2, n):
        self.a1 = a1
        self.a2 = a2
        self.b1 = b1
        self.b2 = b2
        self.n = n
        self.pubkey = None

    def generate_private_key(self):
        x = pollard_eqs_solver(self.a1, self.b1, self.a2, self.b2, self.n)
        return PrivateKey(self.pubkey.p, self.pubkey.g, x, self.pubkey.bit_length)


class SimplePRMiner:
    """A pollard rho miner uses textbook mapping functions to search private key."""
    def __init__(self, block: Block, block_time=0):
        self.block = block
        self.block_time = block_time

    def header_hash(self, nonce: int) -> int:
        self.block.nonce = nonce
        hash_val = int.from_bytes(self.block.hash_header(), byteorder='little', signed=True) % self.block.public_key.p
        return hash_val

    def func_f(self, hash_i, y_i):
        """x_(i+1) = func_f(hash(x_i))"""
        base = self.block.public_key.g
        h = self.block.public_key.h
        p = self.block.public_key.p
        if hash_i % 3 == 2:
            return (h * y_i) % p
        elif hash_i % 3 == 0:
            return pow(y_i, 2, p)
        elif hash_i % 3 == 1:
            return base * y_i % p
        else:
            raise ValueError("Input value has error!")

    def func_g(self, a, n, hash_i):
        """Wrapper of classic mapping function for a."""
        p = self.block.public_key.p
        return func_g(a, n, p, hash_i)

    def func_h(self, b, n, hash_i):
        """Wrapper of classic mapping function for b."""
        p = self.block.public_key.p
        return func_h(b, n, p, hash_i)

    @staticmethod
    def _calculate_y(a, b, g, h, p):
        return (pow(g, a, p) * pow(h, b, p)) % p

    def mining(self) -> tuple[int, Optional[PRSolution]]:
        """
        Refer to section 3.6.3 of Handbook of Applied Cryptography
        Computes `x` = a mod n for the DLP base**x % p == y
        in the Group G = {0, 1, 2, ..., n}
        given that order `n` is a prime number.

        Returns:
            nonce and paired private key
        """
        pubkey = self.block.public_key
        n = (pubkey.p - 1) // 2

        a_i = randint(0, n)
        b_i = randint(0, n)
        a_2i = a_i
        b_2i = b_i

        y_i = self._calculate_y(a_i, b_i, pubkey.g, pubkey.h, pubkey.p)
        y_2i = y_i

        i = 1
        init_time = time.time()
        while i <= n and (time.time() - init_time) < self.block_time:
            # Single Step calculations
            hash_1i = self.header_hash(y_i)
            a_i = self.func_g(a_i, n, hash_1i)
            b_i = self.func_h(b_i, n, hash_1i)
            y_i = self.func_f(hash_1i, y_i)
            # print(f"y: {y_i}, a: {a_i}, b: {b_i}")
            # assert(y_i == self._calculate_y(a_i, b_i, pubkey.g, pubkey.h, pubkey.p))

            # Double Step calculations
            hash_2mi = self.header_hash(y_2i)
            a_2i = self.func_g(a_2i, n, hash_2mi)
            b_2i = self.func_h(b_2i, n, hash_2mi)
            y_2mi = self.func_f(hash_2mi, y_2i)
            hash_2i = self.header_hash(y_2mi)
            a_2i = self.func_g(a_2i, n, hash_2i)
            b_2i = self.func_h(b_2i, n, hash_2i)
            y_2i = self.func_f(hash_2i, y_2mi)
            # assert (y_2i == self._calculate_y(a_2i, b_2i, pubkey.g, pubkey.h, pubkey.p))

            if y_i == y_2i:
                # print("left side = ", (pow(pubkey.g, a_i, pubkey.p) * pow(pubkey.h, b_i, pubkey.p)) % pubkey.p)
                # print("right side = ", (pow(pubkey.g, a_2i, pubkey.p) * pow(pubkey.h, b_2i, pubkey.p)) % pubkey.p)
                solution = PRSolution(a_i, a_2i, b_i, b_2i, n)
                solution.pubkey = pubkey
                return y_2mi, solution
            else:
                i += 1
                continue
        # failed to find the solution and nonce, return none
        return 0, None


class PRMiner(SimplePRMiner):
    """The pollard rho miner with a mapping function which is hard to compute reversely."""
    def func_f(self, hash_i, y_i):
        base = self.block.public_key.g
        h = self.block.public_key.h
        p = self.block.public_key.p
        if hash_i % 3 == 2:
            return (pow(h, hash_i, p) * y_i) % p
        elif hash_i % 3 == 0:
            return pow(y_i, hash_i, p)
        elif hash_i % 3 == 1:
            return (pow(base, hash_i, p) * y_i) % p
        else:
            raise ValueError("Input value has error!")

    def func_g(self, a, n, hash_i):
        p = self.block.public_key.p
        if hash_i % 3 == 2:
            return a
        elif hash_i % 3 == 0:
            return a * hash_i % (p-1)
        elif hash_i % 3 == 1:
            return (a + hash_i) % (p-1)
        else:
            raise ValueError("Input value has error!")

    def func_h(self, b, n, hash_i):
        p = self.block.public_key.p
        if hash_i % 3 == 2:
            return (b + hash_i) % (p-1)
        elif hash_i % 3 == 0:
            return b * hash_i % (p-1)
        elif hash_i % 3 == 1:
            return b
        else:
            raise ValueError("Input value has error!")
