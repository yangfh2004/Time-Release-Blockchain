import simpleTimeReleaseBlockchain.crypto.elgamal as elgamal
import unittest
import sys


class TestElgamalEncryption(unittest.TestCase):
    def setUp(self) -> None:
        self.pub = elgamal.generate_pub_key(seed=833050814021254693158343911234888353695402778102174580258852673738983005,
                                            bit_length=20)

    def test_pubkey(self):
        self.assertEqual(0x1ff6, self.pub.g, "Public key g part is not correct!")
        self.assertEqual(0x92901, self.pub.h, "Public key h part is not correct!")
        self.assertEqual(0xb8433, self.pub.p, "Public key p part is not correct!")

    def test_python_version(self):
        self.assertTrue(sys.version_info >= (3, 7), "Python version is too low!")

    # test method to demonstrate elgamal DLP encryption
    def test_private_key(self):
        private_key = None
        for i in range(1, self.pub.p):
            if self.pub.h == elgamal.mod_exp(self.pub.g, i, self.pub.p):
                private_key = elgamal.PrivateKey(self.pub.p, self.pub.g, i, self.pub.bit_length)
        # if found private key, assert the key validation
        if private_key:
            message = "Private key is found and here is a test of the elgamal crypto system."
            cipher = elgamal.encrypt(self.pub, message)
            plain = elgamal.decrypt(private_key, cipher)
            self.assertEqual(message, plain, "Private key is not valid!")


if __name__ == '__main__':
    unittest.main()
