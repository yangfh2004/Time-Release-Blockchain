import time
import json
import requests
import signal
from os import environ
from typing import Optional
import dataset
import urllib.parse
from crypto import elgamal
from mining.pollard_rho_hash import PRMiner
from blockchain.block import Block, create_genesis_block
from blockchain.transaction import Tx
from miner_config import BLOCKCHAIN_DB_URL
from dotenv import load_dotenv

load_dotenv()  # take environment variables from .env.
MINER_ADDRESS = environ.get("MINER_ADDRESS")
MINER_NODE_URL = environ.get("MINER_NODE") + ':' + environ.get("MINER_PORT")
PEER_NODES = environ.get("PEER_NODES")

# constant time in seconds that determine how soon the new block will be generated
BLOCK_TIME = 30
flag_ = 0
# How many blocks to adjust the public key size (difficulty level)
term = 120
start_time = 0
# bit length of mining target
difficulty = 32
# mining award
mining_reward = 100


class TimeoutException(Exception):
    # Custom exception class
    pass


def timeout_handler(signum, frame):
    # Custom signal handler
    raise TimeoutException


# Change the behavior of SIGALRM
signal.signal(signal.SIGALRM, timeout_handler)


def calculate_difficulty(bit_length: int):
    """Calculate current difficulty based on previous mining time."""
    global flag_, start_time, BLOCK_TIME

    if flag_ == 0:
        start_time = time.time()
        flag_ = 1

    else:
        if time.time() - start_time > BLOCK_TIME:
            bit_length = bit_length - 1

        elif time.time() - start_time < BLOCK_TIME:
            bit_length = bit_length + 1

        start_time = time.time()

    return bit_length


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
        try:
            solution.generate_private_key()
            candidate_block.solution = solution
            return candidate_block, blockchain
        except ValueError:
            return None, blockchain
    else:
        new_blockchain = consensus(blockchain, peer_nodes)
        if new_blockchain:
            return None, new_blockchain
        else:
            return None, blockchain


def mine(blockchain: list[Block],
         node_pending_txs: list[Tx],
         database,
         debug=False,
         difficulty_adjustable=False):
    """ Stores the transactions that this node has in a list.
    If the node you sent the transaction adds a block
    it will get accepted, but there is a chance it gets
    discarded and your transaction goes back as if it was never
    processed"""
    # declare with global keyword to modify blockchain and pending transactions
    global difficulty
    # database['logs'].insert({'category': 'status', 'timestamp': datetime.now(), 'info': 'start mining!'})
    while True:
        """Mining is the only way that new coins can be created.
        In order to prevent too many coins to be created, the process
        is slowed down by a proof of work algorithm.
        """
        # Start the timer. Once 5 seconds are over, a SIGALRM signal is sent.
        signal.alarm(BLOCK_TIME)
        init_time = time.time()
        try:
            # Get the last proof of work
            last_block = blockchain[-1]
            if difficulty_adjustable:
                if (last_block.height + 2) % term == 2:
                    difficulty = calculate_difficulty(last_block.difficulty)
            # use url parser to avoid url encoding error e.g. + -> space
            req = MINER_NODE_URL + "/txion?update=" + urllib.parse.quote(MINER_ADDRESS)
            # database['logs'].insert({'category': 'request', 'timestamp': datetime.now(), 'info': req})
            new_txs = requests.get(req).content
            new_txs = json.loads(new_txs)
            # add the mining reward token as coinbase transaction
            node_pending_txs.append(Tx.coinbase(MINER_ADDRESS, mining_reward))
            for tx in list(new_txs):
                node_pending_txs.append(Tx.from_dict(tx))

            new_block_index = last_block.height + 1
            new_block_timestamp = time.time()
            # avoid to recalculate block hash if the block data is retrieved from database
            if last_block.current_block_hash:
                prev_block_hash = last_block.current_block_hash
            else:
                prev_block_hash = last_block.hash_header()
            prev_public_key = last_block.public_key
            # generate new public key with previous public key
            new_public_key = elgamal.generate_pub_key(bit_length=difficulty,
                                                      seed=int(
                                                          prev_public_key.p + prev_public_key.g + prev_public_key.h))
            candidate_block = Block(new_block_index,
                                    new_block_timestamp,
                                    node_pending_txs,
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
                    database['blockchain'].update(bk.get_db_record(), ['height'])
                continue
            else:
                # Once we find a valid proof of work, we know we can mine a block so
                # ...we reward the miner by adding a transaction
                # First we load all pending transactions sent to the node server
                # insert transactions to database
                db_txs = []
                for tx in node_pending_txs:
                    db_tx = tx.__dict__
                    db_tx["block_height"] = new_block_index
                    db_txs.append(db_tx)
                database["transactions"].insert_many(db_txs)
                res_txs = database["transactions"].find(block_height=new_block_index)
                tx_ids = [tx["id"] for tx in res_txs]
                # Empty transaction list
                node_pending_txs = []
                # Now create the new block
                blockchain.append(new_block)
                # insert new block to the database
                database['blockchain'].insert(new_block.get_db_record(tx_ids=tx_ids))
        except TimeoutException:
            continue
        else:
            # if finish mining within block time, sleep for debugging
            if debug:
                # sleep to wait for new tx if for debugging, minus 1 sec to avoid triggering alarm
                sleep_time = BLOCK_TIME - (time.time() - init_time) - 1
                time.sleep(sleep_time)
            signal.alarm(0)


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


def retrieve_chain_from_db(database):
    if len(database['blockchain']) == 0:
        # write the genesis block if the blockchain is empty
        current_chain = [create_genesis_block()]
        database['blockchain'].insert(current_chain[0].get_db_record())
    else:
        # load the whole blockchain from database
        current_chain = []
        for db_block in database['blockchain']:
            current_block = Block.from_db(db_block)
            # recover all Tx objects from db
            tx_id_str = db_block['transactions']
            if tx_id_str is not None and tx_id_str != "[]":
                tx_ids = [int(tx_id) for tx_id in tx_id_str.split(',')]
                db_txs = database['transactions'].find(id=tx_ids)
                txs = []
                for db_tx in db_txs:
                    txs.append(Tx.from_dict(db_tx))
                current_block.transactions = txs
            current_chain.append(current_block)
    return current_chain


if __name__ == '__main__':
    welcome_msg()
    # if first time running, use the genesis block
    db = dataset.connect(BLOCKCHAIN_DB_URL)
    # Start mining
    mine(retrieve_chain_from_db(db), [], db, debug=True)
