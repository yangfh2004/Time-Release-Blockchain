import time
import hashlib
import json
import requests
import base64
from flask import Flask, request
from multiprocessing import Process, Pipe
import ecdsa
import argparse
# import codecs
from simpleTimeReleaseBlockchain.crypto import elgamal
from typing import Optional

node = Flask(__name__)

# constant time in seconds that determine how soon the new block will be generated
BLOCK_TIME = 30
flag_ = 0
# How many blocks to adjust the public key size (difficulty level)
term = 5
start_time = 0
# load default miner configuration from local JSON file
MINER_ADDRESS = ""
MINER_NODE_URL = ""
PEER_NODES = []


class Block:
    def __init__(self,
                 height: int,
                 timestamp,
                 transactions,
                 public_key: elgamal.PublicKey,
                 public_key_size,
                 nonce=None,
                 prev_block_hash=None):
        """Init time release block.

        Args:
            height: block height
            timestamp:
            transactions: all valid transactions in this block
            public_key: next public key for time release
            public_key_size: elgamal public key size as the difficulty
            nonce:
            prev_block_hash: hash of previous block header
        """
        self.version = 1.0
        self.index = height
        self.timestamp = timestamp
        self.transactions = transactions
        self.difficult = public_key.p
        self.prev_block_hash = prev_block_hash
        self.nonce = nonce
        self.difficulty = public_key_size
        self.public_key = public_key
        # the static hash is the sha256 object to calculate header hash with different nonce without reallocation
        self._static_hash = hashlib.sha256()
        self._static_hash.update((str(self.index) + str(self.timestamp) + str(self.body_hash()) +
                                  str(self.public_key)).encode('utf-8'))

    def hash_header(self):
        """Double hash of the block header

        Returns:
            SHA256(SHA256(block_header))
        """
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


def create_genesis_block():
    cipher = elgamal.generate_pub_key(seed=0xffffffffffffff, bit_length=18)
    return Block(0, time.time(), {"transactions": None}, cipher, 18)


# Node's blockchain copy
BLOCKCHAIN = [create_genesis_block()]

""" Stores the transactions that this node has in a list.
If the node you sent the transaction adds a block
it will get accepted, but there is a chance it gets
discarded and your transaction goes back as if it was never
processed"""
NODE_PENDING_TRANSACTIONS = []


def calculate_difficulty(difficulty: int):
    global flag_, start_time, BLOCK_TIME

    if flag_ == 0:
        start_time = time.time()
        flag_ = 1

    else:
        if time.time() - start_time > BLOCK_TIME:
            difficulty = difficulty - 1

        elif time.time() - start_time < BLOCK_TIME:
            difficulty = difficulty + 1

        start_time = time.time()

    return difficulty


def proof_of_work(last_block: Block,
                  candidate_block: Block,
                  blockchain: list[Block]) -> tuple[Optional[Block], list[Block]]:
    """Find private key by double hash with different nonce values
    TODO: If other nodes are found first, False is returned..

    Args:
        last_block:
        candidate_block:
        blockchain:

    Returns:

    """
    i = 0
    init_time = time.time()
    while True:
        candidate_block.nonce = i

        hash_header = int(candidate_block.hash_header(), last_block.difficulty) % (last_block.public_key.p - 1) + 1

        # test if the header hash is the solution of the discrete log problem
        if last_block.public_key.h == elgamal.mod_exp(last_block.public_key.g, hash_header, last_block.public_key.p):
            break

        if (time.time() - init_time) > BLOCK_TIME:
            init_time = time.time()
            new_blockchain = consensus(blockchain)
            if new_blockchain:
                return None, new_blockchain
        i = i + 1
    return candidate_block, blockchain


def mine(connection,
         blockchain: list[Block],
         node_pending_transactions):
    # declare with global keyword to modify blockchain and pending transactions
    global BLOCKCHAIN, NODE_PENDING_TRANSACTIONS
    BLOCKCHAIN = blockchain
    NODE_PENDING_TRANSACTIONS = node_pending_transactions

    while True:
        """Mining is the only way that new coins can be created.
        In order to prevent too many coins to be created, the process
        is slowed down by a proof of work algorithm.
        """
        # Get the last proof of work
        last_block = blockchain[-1]
        difficulty = 1
        if last_block.index == 0:
            time.sleep(1)

        if (last_block.index + 2) % term == 2:
            difficulty = calculate_difficulty(last_block.difficulty)

        NODE_PENDING_TRANSACTIONS = requests.get(MINER_NODE_URL + "/txion?update=" + MINER_ADDRESS).content
        NODE_PENDING_TRANSACTIONS = json.loads(NODE_PENDING_TRANSACTIONS)
        NODE_PENDING_TRANSACTIONS.append({"from": "network", "to": MINER_ADDRESS, "amount": 1})
        new_transactions = {"transactions": list(NODE_PENDING_TRANSACTIONS)}

        new_block_index = last_block.index + 2
        new_block_timestamp = time.time()
        prev_block_hash = blockchain[-1].hash_header()
        prev_public_key = blockchain[-1].public_key
        # generate new public key with previous public key
        new_public_key = elgamal.generate_pub_key(bit_length=difficulty,
                                                  seed=int(prev_public_key.p + prev_public_key.g + prev_public_key.h))
        candidate_block = Block(new_block_index,
                                new_block_timestamp,
                                new_transactions,
                                new_public_key,
                                difficulty,
                                prev_block_hash=prev_block_hash)

        # Find the proof of work for the current block being mined
        # Note: The program will hang here until a new proof of work is found
        proof = proof_of_work(last_block, candidate_block, blockchain)
        # If we didn't guess the proof, start mining again
        if not proof[0]:
            # Update blockchain and save it to file
            blockchain = proof[1]
            connection.send(blockchain)
            continue
        else:
            # Once we find a valid proof of work, we know we can mine a block so
            # ...we reward the miner by adding a transaction
            # First we load all pending transactions sent to the node server

            '''
            # Then we add the mining reward
            NODE_PENDING_TRANSACTIONS.append({
                "from": "network",
                "to": MINER_ADDRESS,
                "amount": 1})
            # Now we can gather the data needed to create the new block
            '''
            # Empty transaction list

            NODE_PENDING_TRANSACTIONS = []
            # Now create the new block                    
            blockchain.append(proof[0])
            # print("before_public_key = " + str(proof[0].key.p * proof[0].key.q))
            print(json.dumps({
                "height": str(proof[0].index),
                "timestamp": str(proof[0].timestamp),
                "header_hash": str(proof[0].hash_header()),
                "difficult": str(proof[0].difficulty),
                "prev_block_hash": str(proof[0].prev_block_hash),
                "next_public": "( " + str(hex(proof[0].public_key.g)) + ", " + str(
                    hex(proof[0].public_key.h)) + ", " + str(hex(proof[0].public_key.p)) + " )",
                "nonce": "( " + str(proof[0].nonce) + " )",
                "transactions": proof[0].transactions
            }, indent=4) + "\n")
            connection.send(blockchain)
            requests.get(MINER_NODE_URL + "/blocks?update=" + MINER_ADDRESS)


def find_new_chains():
    # Get the blockchains of every other node
    other_chains = []
    for node_url in PEER_NODES:
        # Get their chains using a GET request
        block = requests.get(node_url + "/blocks").content
        # Convert the JSON object to a Python dictionary
        block = json.loads(block)
        # Verify other node block is correct
        validated = validate_blockchain(block)
        if validated:
            # Add it to our list
            other_chains.append(block)
    return other_chains


def consensus(blockchain) -> Optional[list[Block]]:
    global BLOCKCHAIN
    # Get the blocks from other nodes
    other_chains = find_new_chains()
    # If our chain isn't longest, then we store the longest chain
    BLOCKCHAIN = blockchain
    longest_chain = BLOCKCHAIN
    for chain in other_chains:
        if len(longest_chain) < len(chain):
            longest_chain = chain
    # If the longest chain wasn't ours, then we set our chain to the longest
    if longest_chain == BLOCKCHAIN:
        # Keep searching for proof
        return None
    else:
        # Give up searching proof, update chain and start over again
        BLOCKCHAIN = longest_chain
        return BLOCKCHAIN


def validate_blockchain(block: Block):
    """Validate the submitted chain. If hashes are not correct,
    rULrd9xIYYgm5D1yUHAj9axyrib0R3chDnJJ2lDiKIwCFFAFYWrkXU7sPWY4RLccMcOQQ+KDvPuOxrlkl0Y+1hw==32
    return false
    block(str): json
    """
    print(block)
    return True


@node.route('/blocks', methods=['GET'])
def get_blocks():
    chain_to_send = []
    if request.args.get("update") == MINER_ADDRESS:
        # Load current blockchain. Only you should update your blockchain
        global BLOCKCHAIN
        BLOCKCHAIN = b.recv()
        chain_to_send = BLOCKCHAIN
    # Converts our blocks into dictionaries so we can send them as json objects later
    chain_to_send_json = []
    for block in chain_to_send:
        block = {
            "index": str(block.index),
            "timestamp": str(block.timestamp),
            "body_hash": str(block.body_hash),
            "difficult": str(block.difficult),
            "public_key_size": str(block.difficulty),
            "before_header_hash": str(block.prev_block_hash),
            "next_public": "( " + str(hex(block.public_key.g)) + ", " + str(hex(block.public_key.h)) + ", " + str(
                hex(block.public_key.p)) + " )",
            "nonce": "( " + str(block.nonce) + " )",
            "data": block.transactions
        }
        chain_to_send_json.append(block)

    chain_to_send = json.dumps(chain_to_send_json)
    return chain_to_send
    # Send our chain to whomever requested it


@node.route('/txion', methods=['GET', 'POST'])
def transaction():
    """Each transaction sent to this node gets validated and submitted.
    Then it waits to be added to the blockchain. Transactions only move
    coins, they don't create it.
    """
    if request.method == 'POST':
        # On each new POST request, we extract the transaction data
        new_txion = request.get_json()
        # Then we add the transaction to our list
        if validate_signature(new_txion['from'], new_txion['signature'], new_txion['message']):
            NODE_PENDING_TRANSACTIONS.append(new_txion)
            # Because the transaction was successfully
            # submitted, we log it to our console
            print("New transaction")
            print("FROM: {0}".format(new_txion['from']))
            print("TO: {0}".format(new_txion['to']))
            print("AMOUNT: {0}\n".format(new_txion['amount']))
            # Then we let the client know it worked out
            return "Transaction submission successful\n"
        else:
            return "Transaction submission failed. Wrong signature\n"
    # Send pending transactions to the mining process
    elif request.method == 'GET' and request.args.get("update") == MINER_ADDRESS:
        pending = json.dumps(NODE_PENDING_TRANSACTIONS)
        # Empty transaction list
        NODE_PENDING_TRANSACTIONS[:] = []
        return pending


def validate_signature(public_key, signature, message):
    """Verifies if the signature is correct. This is used to prove
    it's you (and not someone else) trying to do a transaction with your
    address. Called when a user tries to submit a new transaction.
    """
    public_key = (base64.b64decode(public_key)).hex()
    signature = base64.b64decode(signature)
    vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
    # Try changing into an if/else statement as except is too broad.
    try:
        return vk.verify(signature, message.encode())
    except ecdsa.BadSignatureError:
        print(f"Signature {signature} is not valid!")
        return False


def welcome_msg():
    print("""       =========================================\n
        SIMPLE COIN v1.0.0 - BLOCKCHAIN SYSTEM\n
       =========================================\n\n
        You can find more help at: https://github.com/cosme12/SimpleCoin\n
        Make sure you are using the latest version or you may end in
        a parallel chain.\n\n\n""")


if __name__ == '__main__':
    welcome_msg()
    parser = argparse.ArgumentParser(description="Load miner configuration")
    parser.add_argument('-c', '--config', nargs='?',
                        default='default_miner_config.json',
                        type=argparse.FileType('r'),
                        help='miner config file, in JSON format')
    args = parser.parse_args()
    # load default miner configuration from local JSON file
    _miner_config = json.load(args.config)
    MINER_ADDRESS = _miner_config["MINER_ADDRESS"]
    MINER_NODE_URL = _miner_config["MINER_NODE_URL"]
    PEER_NODES = _miner_config["PEER_NODES"]
    args.config.close()
    # Start mining
    a, b = Pipe()
    p1 = Process(target=mine, args=(a, BLOCKCHAIN, NODE_PENDING_TRANSACTIONS))
    p1.start()
    # Start server to receive transactions
    p2 = Process(target=node.run(), args=(b,))
    p2.start()
