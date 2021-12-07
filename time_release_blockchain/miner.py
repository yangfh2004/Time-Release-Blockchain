import time
import json
import requests
import base64
from flask import Flask, request
from multiprocessing import Process, Pipe
from typing import Optional
import ecdsa
import argparse
from os import environ
# import codecs
from time_release_blockchain.crypto import elgamal
from time_release_blockchain.mining.pollard_rho_hash import PRMiner
from time_release_blockchain.block import Block, create_genesis_block

node = Flask(__name__)
a, b = Pipe()
node.config['CONNECTION'] = b

# constant time in seconds that determine how soon the new block will be generated
BLOCK_TIME = 30
flag_ = 0
# How many blocks to adjust the public key size (difficulty level)
term = 120
start_time = 0
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
                  blockchain: list[Block],
                  peer_nodes) -> tuple[Optional[Block], list[Block]]:
    """Find private key by double hash with different nonce values
    TODO: If other nodes are found first, False is returned..

    Args:
        last_block:
        candidate_block:
        blockchain:
        peer_nodes:

    Returns:

    """
    miner = PRMiner(candidate_block)
    nonce, solution = miner.mining()
    if nonce and solution:
        private_key = solution.generate_private_key()
        prime = last_block.public_key.p
        expected = last_block.public_key.h
        actual = elgamal.mod_exp(last_block.public_key.g, private_key.x, prime)
        # test if the private key match the public key
        if expected == actual or prime == expected + actual:
            return candidate_block, blockchain
    else:
        new_blockchain = consensus(blockchain, peer_nodes)
        if new_blockchain:
            return None, new_blockchain


def mine(connection,
         blockchain: list[Block],
         node_pending_transactions,
         miner_config):
    # declare with global keyword to modify blockchain and pending transactions
    global BLOCKCHAIN, NODE_PENDING_TRANSACTIONS
    miner_address = miner_config["MINER_ADDRESS"]
    miner_node_url = miner_config["MINER_NODE_URL"]
    peer_nodes = miner_config["PEER_NODES"]
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

        NODE_PENDING_TRANSACTIONS = requests.get(miner_node_url + "/txion?update=" + miner_address).content
        NODE_PENDING_TRANSACTIONS = json.loads(NODE_PENDING_TRANSACTIONS)
        # add the mining reward 1 token as coinbase transaction
        NODE_PENDING_TRANSACTIONS.append({"from": "network", "to": miner_address, "amount": 1})
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
                                prev_block_hash=prev_block_hash)

        # Find the proof of work for the current block being mined
        # Note: The program will hang here until a new proof of work is found
        proof = proof_of_work(last_block, candidate_block, blockchain, peer_nodes)
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
            requests.get(miner_node_url + "/blocks?update=" + miner_address)


def find_new_chains(peer_nodes):
    # Get the blockchains of every other node
    other_chains = []
    for node_url in peer_nodes:
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


def consensus(blockchain, peer_nodes) -> Optional[list[Block]]:
    global BLOCKCHAIN
    # Get the blocks from other nodes
    other_chains = find_new_chains(peer_nodes)
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
    connection = node.config['CONNECTION']
    miner_address = environ.get('MINER_ADDRESS')
    if request.args.get("update") == miner_address:
        # Load current blockchain. Only you should update your blockchain
        global BLOCKCHAIN
        BLOCKCHAIN = connection.recv()
        chain_to_send = BLOCKCHAIN
    # Converts our blocks into dictionaries so we can send them as json objects later
    chain_to_send_json = []
    for block in chain_to_send:
        block = {
            "index": str(block.index),
            "timestamp": str(block.timestamp),
            "body_hash": str(block.body_hash),
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
    miner_address = environ.get("MINER_ADDRESS")
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
    elif request.method == 'GET' and request.args.get("update") == miner_address:
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
        NEXTOKEN v0.0.1 - TIME RELEASE BLOCKCHAIN SYSTEM\n
       =========================================\n\n
        You can find more help at: https://github.com/yangfh2004/Time-Release-Blockchain\n
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
    args.config.close()
    # Start mining
    p1 = Process(target=mine, args=(a, BLOCKCHAIN, NODE_PENDING_TRANSACTIONS, _miner_config))
    p1.start()
    # Start server to receive transactions
    node.run(debug=True)
