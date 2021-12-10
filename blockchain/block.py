import time
import hashlib
import crypto.elgamal as elgamal
from mining.pollard_rho_solution import PRSolution


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
                 solution: PRSolution = None,
                 prev_block_hash=None):
        """Init time release block.

        Args:
            height: block height
            timestamp: unix timestamp
            transactions: all valid transactions in this block
            public_key: next public key for time release
            nonce: nonce value for mining
            solution: solution for deriving private key
            prev_block_hash: hash of previous block header
        """
        self.version = 1.0
        self.height = height
        self.timestamp = timestamp
        self.transactions = transactions
        self.prev_block_hash = prev_block_hash
        self.nonce = nonce
        self.solution = solution
        self.difficulty = public_key.bit_length
        self.public_key = public_key
        # the static hash is the sha256 object to calculate header hash with different nonce without reallocation
        self._static_hash = None
        # this static header hash is for database retrieved block only, so that do not recalculate hash value
        self.current_block_hash = None

    @classmethod
    def from_db(cls, db_block: dict):
        """
        Generate a Block obj from database data.
        Args:
            db_block: database block data.

        Returns:
            new Block obj.
        """
        pub_key = elgamal.PublicKey.from_hex_str(db_block['public_key'])
        block = Block(height=db_block['height'],
                      timestamp=db_block['timestamp'],
                      transactions=[],
                      public_key=pub_key,
                      prev_block_hash=db_block['prev_block_hash'])
        if db_block["solution"]:
            block.solution = PRSolution.from_str(db_block['solution'])
        block.current_block_hash = db_block['header_hash']
        return block

    def get_db_record(self, tx_ids: list[int] = None):
        """Dump object as dict for database insertion."""
        db_record = {
                "height": self.height,
                "timestamp": self.timestamp,
                "header_hash": self.hash_header(),
                "difficulty": self.difficulty,
                "prev_block_hash": self.prev_block_hash,
                "public_key": repr(self.public_key),
                "nonce": self.nonce
            }
        if tx_ids:
            db_record["transactions"] = ", ".join(str(tx_id) for tx_id in tx_ids)
        if self.solution:
            db_record["solution"] = repr(self.solution)
        return db_record

    def hash_header(self):
        """Double hash of the block header

        Returns:
            SHA256(SHA256(block_header))
        """
        if not self._static_hash:
            # if the static hash is not yet allocated, do it here, the hash obj cannot be serialized so the init is not
            # inside __init__
            self._static_hash = hashlib.sha256()
            self._static_hash.update((str(self.height) + str(self.timestamp) + str(self.body_hash()) +
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
