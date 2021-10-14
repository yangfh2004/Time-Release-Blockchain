import time_release_blockchain.crypto.elgamal as elgamal
from time_release_blockchain.mining.pollard_rho_hash import PRSolution, SimplePRMiner
from time_release_blockchain.miner import Block
import unittest
import time


class TestMining(unittest.TestCase):
    def setUp(self) -> None:
        # TODO: with certain seeds, the found private keys does not match the public key but meet following equation
        # h + pow(g, private_key, p) = p, the root cause of this problem is not yet clear,
        self.test_pubkey = elgamal.generate_pub_key(0xffffffffffff, 32)
        # generate genesis block
        self.test_block = Block(0, time.time(), {"transactions": None}, self.test_pubkey)
        self.test_miner = SimplePRMiner(self.test_block)

    def test_simple_miner(self):
        # number of blocks to be mined
        block_len = 10
        for _ in range(block_len):
            nonce, solution = self.test_miner.mining()
            private_key = solution.generate_private_key()
            prime = self.test_block.public_key.p
            expected = self.test_block.public_key.h
            actual = elgamal.mod_exp(self.test_block.public_key.g, private_key.x, prime)
            # print("Expected = ", expected)
            # print("Actual = ", actual)
            # print("Prime = ", prime)
            self.assertEqual(expected, actual)
            self.test_block.nonce = nonce
            self.test_pubkey = elgamal.generate_pub_key(seed=int(self.test_pubkey.p + self.test_pubkey.g +
                                                                 self.test_pubkey.h),
                                                        bit_length=self.test_pubkey.bit_length)
