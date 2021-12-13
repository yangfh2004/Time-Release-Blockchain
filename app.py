import json
import time
import miner
from multiprocessing import Process
from flask import Flask, request, jsonify
from os import environ
import dataset
from binascii import hexlify
from miner_config import BLOCKCHAIN_DB_URL
from crypto.tx_sign import validate_signature
from dotenv import load_dotenv
# load env var from .env
load_dotenv()
node = Flask(__name__)
""" Stores the transactions that this node has in a list.
If the node you sent the transaction adds a block
it will get accepted, but there is a chance it gets
discarded and your transaction goes back as if it was never
processed"""
NODE_PENDING_TRANSACTIONS = []
db = dataset.connect(BLOCKCHAIN_DB_URL)


def hexlify_block(db_block: dict):
    """Hexlify block header hash from bytes to hex string."""
    # convert bytes data to hex string
    if db_block['prev_block_hash']:
        db_block['prev_block_hash'] = hexlify(db_block['prev_block_hash']).decode('ascii')
    db_block['header_hash'] = hexlify(db_block['header_hash']).decode('ascii')
    return db_block


@node.route("/")
def index():
    return "<h1>NexToken Time Release Blockchain System</h1>"


@node.route('/blocks', methods=['GET'])
def get_blocks():
    # Converts our blocks into dictionaries so we can send them as json objects later
    chain_to_send = []
    for block in db['blockchain']:
        chain_to_send.append(hexlify_block(block))
        # recover all Tx objects from db
        tx_id_str = block['transactions']
        if tx_id_str is not None:
            tx_ids = [int(tx_id) for tx_id in tx_id_str.split(',')]
            db_txs = [db_tx for db_tx in db['transactions'].find(id=tx_ids)]
            block['transactions'] = db_txs
    return jsonify(chain_to_send)
    # Send our chain to whomever requested it


@node.route('/last', methods=['GET'])
def get_last_block():
    last_block_idx = len(db['blockchain'])
    if last_block_idx > 0:
        last_block = db['blockchain'].find_one(id=last_block_idx)
        return jsonify(hexlify_block(last_block))
    else:
        last_block = {"height": 0}
        return jsonify(last_block)


@node.route('/logs', methods=['GET'])
def get_logs():
    logs = []
    for log in db['logs']:
        log['timestamp'] = log['timestamp'].strftime("%m/%d/%Y %H:%M:%S")
        logs.append(log)
    return json.dumps(logs)


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
        # validate the new transaction before put it on the list
        tx_pub_key = new_txion['addr_from']
        tx_signature = new_txion['signature']
        tx_data = {
            "addr_from": new_txion['addr_from'],
            "addr_to": new_txion['addr_to'],
            "amount": new_txion['amount'],
        }
        if validate_signature(tx_pub_key, tx_signature, json.dumps(tx_data)):
            # Then we add the transaction to our list
            NODE_PENDING_TRANSACTIONS.append(new_txion)
            # Because the transaction was successfully
            # submitted, we log it to our console
            print("New transaction")
            print(f"FROM: {new_txion['addr_from']}")
            print(f"TO: {new_txion['addr_to']}")
            print("AMOUNT: {0}".format(new_txion['amount']))
            if "cipher" in new_txion and "release_block_idx" in new_txion:
                print(f"This transaction contains cipher message "
                      f"to be released in block {new_txion['release_block_idx']}\n")
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


if __name__ == '__main__':
    # THIS PART OF CODE SHALL ONLY RUN IN DEPLOYMENT AS PYTHON SCRIPT DIRECTLY
    # DO NOT RUN THE MAIN FUNCTION IF YOU ARE UNDER DEVELOPMENT/DEBUGGING MODE
    # load port from .env
    # TODO: need a deployment test
    port = environ.get("MINER_PORT")
    from waitress import serve
    p1 = Process(target=serve, args=(node,), kwargs={"port": port})
    p1.run()
    # run miner after setup the node
    # wait 5 sec until the server fully setup
    time.sleep(5)
    miner.welcome_msg()
    p2 = Process(target=miner.mine, args=(miner.retrieve_chain_from_db(db), [], db, True))
    p2.run()
