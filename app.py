import json
import time
from flask import Flask, request, jsonify, make_response
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
    """
    Get blocks with 'start' and 'end' height index (NOT id IN SQLITE DB!).
    Note: the upper limit index is exclusive and lower one is inclusive.
    e.g. if want to get blocks with heights [0, 1, 2] use parameters {start: 0, end: 3}
    if 'start' index is not provided, the default start height is 0.
    if 'end' index is not provided, the default end height is the max height
    if none of them is provided, the full blockchain will be sent.

    Returns:
        blockchain in json format
    """

    args = request.args
    start = args.get("start", type=int)
    end = args.get("end", type=int)
    # Converts our blocks into dictionaries so we can send them as json objects later
    chain_to_send = []
    if start is None:
        # index is not valid return empty chain
        start = 0
    if end is None:
        end = len(db['blockchain'])
    if start < end:
        for block in db['blockchain'].find(id={'between': [start+1, end]}):
            # Note: height = block_id - 1
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


def tx_res_text(sig_valid: bool, tx_valid: bool):
    if sig_valid and tx_valid:
        return "Transaction submission successful\n"
    if not sig_valid:
        return "Transaction submission failed. Wrong signature\n"
    return "Transaction submission failed. Balance not enough\n"


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
        tx_json = json.dumps(tx_data, separators=(',', ':'))
        sig_validation = validate_signature(tx_pub_key, tx_signature, tx_json)
        tx_validation = validate_transaction(db, tx_data)
        if sig_validation and tx_validation:
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
        response = make_response(tx_res_text(sig_validation, tx_validation), 200)
        response.mimetype = "text/plain"
        return response
    # Send pending transactions to the mining process
    elif request.method == 'GET' and request.args.get("update") == miner_address:
        pending = json.dumps(NODE_PENDING_TRANSACTIONS)
        # Empty transaction list
        NODE_PENDING_TRANSACTIONS[:] = []
        return pending


def validate_transaction(database, tx: dict):
    in_sum = 0
    # sum all txs inbound to this address
    for db_tx in database['transactions'].find(addr_to=tx["addr_from"]):
        in_sum += db_tx['amount']
    # sum all txs outbound from this address
    out_sum = 0
    for db_tx in database['transactions'].find(addr_from=tx["addr_from"]):
        out_sum += db_tx['amount']
    balance = in_sum - out_sum
    tx_amount = int(tx["amount"])
    if tx_amount <= balance:
        return True
    else:
        return False


if __name__ == '__main__':
    # THIS PART OF CODE SHALL ONLY RUN IN DEPLOYMENT AS PYTHON SCRIPT DIRECTLY
    # DO NOT RUN THE MAIN FUNCTION IF YOU ARE UNDER DEVELOPMENT/DEBUGGING MODE
    # load port from .env
    # TODO: need a deployment test
    # Note: Miner is not working with 'flask run' due to a bug in Flask SocketIO
    import miner
    from multiprocessing import Process
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
