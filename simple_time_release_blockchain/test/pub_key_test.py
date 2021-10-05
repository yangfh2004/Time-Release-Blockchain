import simple_time_release_blockchain.crypto.elgamal as elgamal
import unittest
import copy


class TestPubKey(unittest.TestCase):
    def setUp(self) -> None:
        # test with a big prime number
        self._seed = 833050814021254693158343911234888353695402778102174580258852673738983005
        self._pub_length = 100
        self._bit_length = 32
        self.genesis_pub = elgamal.generate_pub_key(seed=self._seed, bit_length=self._bit_length)
        self.pub_list = []
        pub = self.genesis_pub
        for _ in range(self._pub_length):
            pub = elgamal.generate_pub_key(seed=int(pub.p + pub.g + pub.h), bit_length=self._bit_length)
            self.pub_list.append(copy.copy(pub))

    def test_fast_private_search(self):
        """Test fast algorithm to find private key in fast"""
        pub_list = [elgamal.PublicKey(37, 5, 24),
                    elgamal.PublicKey(1898959, 3, 844405),
                    elgamal.PublicKey(5898931, 7, 5110965)]
        private_list = [31, 8412, 50000]
        for pub, private in zip(pub_list, private_list):
            self.assertEqual(private, elgamal.fast_search_private_key(pub).x)

    @unittest.skip("May skip brute force test to save time")
    def test_pub_validation(self):
        """Test if generated public key can find its paired private key."""
        for pub in self.pub_list:
            self.assertTrue(elgamal.find_private_key(pub) is not None, "Cannot find pub key's paired private key, "
                                                                       "the pub key is not valid!")

    def test_pub_repeatability(self):
        """Test if the public key generator can repeat its results."""
        pub = self.genesis_pub
        for i in range(self._pub_length):
            pub = elgamal.generate_pub_key(seed=int(pub.p + pub.g + pub.h), bit_length=self._bit_length)
            self.assertEqual(pub, self.pub_list[i], "The public key generator is not repeatable!")
