import crypto.elgamal as elgamal
from mining.pollard_rho_hash import PRMiner, SimplePRMiner
from blockchain.block import Block
import unittest
import time


class TestMining(unittest.TestCase):
    def setUp(self) -> None:
        test_pubkey = elgamal.generate_pub_key(0xffffffffffff, 32)
        # generate genesis block
        self.test_block = Block(0, time.time(), [], test_pubkey)
        self.test_miner = None
        self.test_block_time = 600

    def _block_mining(self):
        nonce, solution = self.test_miner.mining()
        private_key = solution.generate_private_key()
        generator = self.test_block.public_key.g
        prime = self.test_block.public_key.p
        expected = self.test_block.public_key.h
        actual = elgamal.mod_exp(generator, private_key.x, prime)
        # test if g is the generator of the group
        # for i in range(1, solution.n - 1):
        #     if pow(generator, i, solution.n) == 1:
        #         print(f"Generator {generator} is a group of {i} for h = {expected} and p = {prime}")
        #         break
        # print("Expected = ", expected)
        # print("Actual = ", actual)
        # print("Prime = ", prime)
        self.assertTrue(expected == actual)
        self.test_block.public_key = elgamal.generate_pub_key(seed=int(self.test_block.public_key.p +
                                                                       self.test_block.public_key.g +
                                                                       self.test_block.public_key.h),
                                                              bit_length=self.test_block.public_key.bit_length)

    @unittest.skip("Simple miner has been verified")
    def test_simple_miner(self):
        """Test simple but unsecured mining method."""
        self.test_miner = SimplePRMiner(self.test_block, self.test_block_time)
        # number of blocks to be mined
        block_len = 5
        for _ in range(block_len):
            self._block_mining()

    def test_safe_miner(self):
        """Test safe mining method."""
        self.test_miner = PRMiner(self.test_block, self.test_block_time)
        block_len = 5
        for _ in range(block_len):
            self._block_mining()
