import time
import json
import requests
from datetime import datetime
from typing import Optional
import dataset
import urllib.parse
from crypto import elgamal
from mining.pollard_rho_hash import PRMiner
from block import Block, create_genesis_block
from miner_config import MINER_ADDRESS, MINER_NODE_URL, PEER_NODES, BLOCKCHAIN_DB_URL

# constant time in seconds that determine how soon the new block will be generated
BLOCK_TIME = 30
flag_ = 0
# How many blocks to adjust the public key size (difficulty level)
term = 120
start_time = 0

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


def proof_of_work(candidate_block: Block,
                  blockchain: list[Block],
                  peer_nodes) -> tuple[Optional[Block], list[Block]]:
    """Find private key by double hash with different nonce values
    TODO: If other nodes are found first, False is returned..

    Args:
        candidate_block:
        blockchain:
        peer_nodes:

    Returns:

    """
    miner = PRMiner(candidate_block, block_time=BLOCK_TIME)
    nonce, solution = miner.mining()
    if nonce and solution:
        private_key = solution.generate_private_key()
        prime = candidate_block.public_key.p
        expected = candidate_block.public_key.h
        actual = elgamal.mod_exp(candidate_block.public_key.g, private_key.x, prime)
        # test if the private key match the public key
        if expected == actual or prime == expected + actual:
            return candidate_block, blockchain
        else:
            return None, blockchain
    else:
        new_blockchain = consensus(blockchain, peer_nodes)
        if new_blockchain:
            return None, new_blockchain
        else:
            return None, blockchain


def mine(blockchain: list[Block],
         node_pending_transactions,
         database):
    # declare with global keyword to modify blockchain and pending transactions
    global NODE_PENDING_TRANSACTIONS
    NODE_PENDING_TRANSACTIONS = node_pending_transactions
    database['logs'].insert({'category': 'status', 'timestamp': datetime.now(), 'info': 'start mining!'})
    while True:
        """Mining is the only way that new coins can be created.
        In order to prevent too many coins to be created, the process
        is slowed down by a proof of work algorithm.
        """
        # Get the last proof of work
        last_block = blockchain[-1]
        difficulty = 32
        if last_block.index == 0:
            time.sleep(1)

        if (last_block.index + 2) % term == 2:
            difficulty = calculate_difficulty(last_block.difficulty)
        # use url parser to avoid url encoding error e.g. + -> space
        req = MINER_NODE_URL + "/txion?update=" + urllib.parse.quote(MINER_ADDRESS)
        database['logs'].update({'category': 'request', 'timestamp': datetime.now(), 'info': req}, ['category'])
        NODE_PENDING_TRANSACTIONS = requests.get(req).content
        NODE_PENDING_TRANSACTIONS = json.loads(NODE_PENDING_TRANSACTIONS)
        # add the mining reward 1 token as coinbase transaction
        NODE_PENDING_TRANSACTIONS.append({"from": "network", "to": MINER_ADDRESS, "amount": 1})
        new_transactions = list(NODE_PENDING_TRANSACTIONS)

        new_block_index = last_block.index + 1
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
        new_block, updated_blockchain = proof_of_work(candidate_block, blockchain, PEER_NODES)
        # If we didn't guess the proof, start mining again
        if new_block is None:
            # Update blockchain and save it to file
            blockchain = updated_blockchain
            # update blockchain in the db
            for bk in blockchain:
                database['blockchain'].update(bk.get_dict(), ['height'])
            continue
        else:
            # Once we find a valid proof of work, we know we can mine a block so
            # ...we reward the miner by adding a transaction
            # First we load all pending transactions sent to the node server
            # Empty transaction list
            NODE_PENDING_TRANSACTIONS = []
            # Now create the new block
            blockchain.append(new_block)
            # insert new block to the database
            database['blockchain'].insert(new_block.get_dict())


def find_new_chains(peer_nodes):
    # TODO: this method needs to convert json to block obj
    # Get the blockchains of every other node
    other_chains = []
    for node_url in peer_nodes:
        # Get their chains using a GET request
        other_blockchain = requests.get(node_url + "/blocks").content
        # Convert the JSON object to a Python dictionary
        other_blockchain = json.loads(other_blockchain)
        # Verify other node block is correct
        validated = validate_blockchain(other_blockchain)
        if validated:
            # Add it to our list
            other_chains.append(other_blockchain)
    return other_chains


def consensus(blockchain, peer_nodes) -> Optional[list[Block]]:
    # Get the blocks from other nodes
    other_chains = find_new_chains(peer_nodes)
    # If our chain isn't longest, then we store the longest chain
    longest_chain = blockchain
    for chain in other_chains:
        if len(longest_chain) < len(chain):
            longest_chain = chain
    # If the longest chain wasn't ours, then we set our chain to the longest
    if longest_chain == blockchain:
        # Keep searching for proof
        return None
    else:
        # Give up searching proof, update chain and start over again
        return longest_chain


def validate_blockchain(blockchain: list[Block]):
    """TODO: Validate the submitted chain. If hashes are not correct"""
    print(blockchain)
    return True


def welcome_msg():
    print("""       =========================================\n
        NEXTOKEN v0.0.1 - TIME RELEASE BLOCKCHAIN SYSTEM\n
       =========================================\n\n
        You can find more help at: https://github.com/yangfh2004/Time-Release-Blockchain\n
        Make sure you are using the latest version or you may end in
        a parallel chain.\n\n\n""")


if __name__ == '__main__':
    welcome_msg()
    # if first time running, use the genesis block
    db = dataset.connect(BLOCKCHAIN_DB_URL)
    if len(db['blockchain']) == 0:
        current_chain = [create_genesis_block()]
        db['blockchain'].insert(current_chain[0].get_dict())
    else:
        current_chain = []
        for db_block in db['blockchain']:
            pub_key = elgamal.PublicKey.from_hex_str(db_block['public_key'], db_block['difficulty'])
            block = Block(height=db_block['height'],
                          timestamp=db_block['timestamp'],
                          transactions=[],
                          public_key=pub_key,
                          prev_block_hash=db_block['prev_block_hash'])
            block.current_block_hash = db_block['header_hash']
            current_chain.append(block)

    # Start mining
    mine(current_chain, NODE_PENDING_TRANSACTIONS, db)
