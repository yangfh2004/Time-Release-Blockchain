import json
import base64
from flask import Flask, request, jsonify
import ecdsa
from os import environ
import dataset
from binascii import hexlify
from miner_config import BLOCKCHAIN_DB_URL
node = Flask(__name__)
""" Stores the transactions that this node has in a list.
If the node you sent the transaction adds a block
it will get accepted, but there is a chance it gets
discarded and your transaction goes back as if it was never
processed"""
NODE_PENDING_TRANSACTIONS = []


@node.route('/blocks', methods=['GET'])
def get_blocks():
    # Converts our blocks into dictionaries so we can send them as json objects later
    chain_to_send = []
    db = dataset.connect(BLOCKCHAIN_DB_URL)
    for block in db['blockchain']:
        # convert bytes data to hex string
        if block['prev_block_hash']:
            block['prev_block_hash'] = hexlify(block['prev_block_hash']).decode('ascii')
        block['header_hash'] = hexlify(block['header_hash']).decode('ascii')
        chain_to_send.append(block)
    return jsonify(chain_to_send)
    # Send our chain to whomever requested it


@node.route('/logs', methods=['GET'])
def get_logs():
    db = dataset.connect(BLOCKCHAIN_DB_URL)
    logs = []
    for log in db['logs']:
        log['timestamp'] = log['timestamp'].strftime("%d/%m/%Y %H:%M:%S")
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


if __name__ == '__main__':
    # Start server to receive transactions
    node.run()
