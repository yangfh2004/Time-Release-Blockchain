import time_release_blockchain.crypto.elgamal as elgamal
from time_release_blockchain.crypto.pollard_rho import pollard_rho
import unittest
import random


class TestPrivateSearch(unittest.TestCase):
    def setUp(self) -> None:
        self._test_len = 10
        self.pub_list = []
        self.private_list = []
        for _ in range(self._test_len):
            _seed = random.randint(2 ** 16, 2 ** 32)
            prime = elgamal.find_prime(32, 32, _seed)
            base = elgamal.find_primitive_root(prime, _seed)
            # the private key shall be within the order of the group
            x = random.randint(2, (prime - 1) // 2)
            h = pow(base, x, prime)
            self.pub_list.append(elgamal.PublicKey(prime, base, h))
            self.private_list.append(x)

    @unittest.skip("May skip basic pollard rho test!")
    def test_pollard_rho(self):
        """Test pollard rho with small numbers"""
        p = 383
        n = (p - 1) // 2
        for i in range(100):
            num = random.randint(2, n)
            y = pow(2, num, p)
            key = pollard_rho(2, y, 383, 191)
            msg = f"The found key {key} is not the original key {num}"
            self.assertEqual(num % n, key, msg)

    def test_bsgs_private_search(self):
        """Test BSGS algorithm to find private key."""
        for pub, private in zip(self.pub_list, self.private_list):
            private_key = elgamal.bsgs_search_private_key(pub)
            self.assertTrue(private_key is not None, "BSGS cannot find the private key!")
            self.assertEqual(private, private_key.x)

    def test_pollard_rho_search(self):
        """Test pollard rho algorithm to search private key."""
        for pub, private in zip(self.pub_list, self.private_list):
            private_key = elgamal.pollard_search_private_key(pub)
            self.assertTrue(private_key is not None, "Pollard rho cannot find the private key!")
            self.assertEqual(private, private_key.x)

    @unittest.skip("May skip naive brute force method to save time")
    def test_pub_validation(self):
        """Test if generated public key can find its paired private key."""
        for pub in self.pub_list:
            self.assertTrue(elgamal.find_private_key(pub) is not None, "Cannot find pub key's paired private key, "
                                                                       "the pub key is not valid!")
