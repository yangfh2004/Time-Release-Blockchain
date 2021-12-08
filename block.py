import time
import hashlib
import crypto.elgamal as elgamal


def create_genesis_block():
    cipher = elgamal.generate_pub_key(0xffffffffffff, 32)
    return Block(0, time.time(), [], cipher)


class Block:
    def __init__(self,
                 height: int,
                 timestamp: float,
                 transactions: list,
                 public_key: elgamal.PublicKey,
                 nonce=None,
                 prev_block_hash=None):
        """Init time release block.

        Args:
            height: block height
            timestamp:
            transactions: all valid transactions in this block
            public_key: next public key for time release
            nonce:
            prev_block_hash: hash of previous block header
        """
        self.version = 1.0
        self.index = height
        self.timestamp = timestamp
        self.transactions = transactions
        self.prev_block_hash = prev_block_hash
        self.nonce = nonce
        self.difficulty = public_key.bit_length
        self.public_key = public_key
        # the static hash is the sha256 object to calculate header hash with different nonce without reallocation
        self._static_hash = None
        # this static header hash is for database retrieved block only, so that do not recalculate hash value
        self.current_block_hash = None

    def get_dict(self):
        return {
            "height": self.index,
            "timestamp": self.timestamp,
            "header_hash": self.hash_header(),
            "difficulty": self.difficulty,
            "prev_block_hash": self.prev_block_hash,
            "public_key": str(hex(self.public_key.g)) + ", " + str(
                hex(self.public_key.h)) + ", " + str(hex(self.public_key.p)),
            "nonce": self.nonce,
            "transactions": str(self.transactions)
        }

    def hash_header(self):
        """Double hash of the block header

        Returns:
            SHA256(SHA256(block_header))
        """
        if not self._static_hash:
            # if the static hash is not yet allocated, do it here, the hash obj cannot be serialized so the init is not
            # inside __init__
            self._static_hash = hashlib.sha256()
            self._static_hash.update((str(self.index) + str(self.timestamp) + str(self.body_hash()) +
                                      str(self.public_key)).encode('utf-8'))
        sha1 = self._static_hash.copy()
        sha1.update(str(self.nonce).encode('utf-8'))
        sha2 = hashlib.sha256()
        sha2.update(sha1.digest())
        return sha2.digest()

    def body_hash(self):
        """Instead of building the Merkel tree, hash all transactions here for simplification.

        Returns:
            SHA256 hash of transactions
        """
        sha = hashlib.sha256()
        sha.update(str(self.transactions).encode('utf-8'))
        return sha.digest()