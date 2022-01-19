"""This is going to be your wallet. Here you can do several things:
- Generate a new address (public and private key). You are going
to use this address (public key) to send or receive any transactions. You can
have as many addresses as you wish, but keep in mind that if you
lose its credential data, you will not be able to retrieve it.

- Send coins to another address
- Retrieve the entire blockchain and check your balance

If this is your first time using this script don't forget to generate
a new address and edit miner config file with it (only if you are
going to mine).

Timestamp in hashed message. When you send your transaction it will be received
by several nodes. If any node mine a block, your transaction will get added to the
blockchain but other nodes still will have it pending. If any node see that your
transaction with same timestamp was added, they should remove it from the
node_pending_transactions list to avoid it get processed more than 1 time.
"""

import json
import requests
import crypto.elgamal as elgamal
from os import environ
from blockchain.block import Block
from crypto.tx_sign import generate_ecdsa_keys, sign_ecdsa_data
from miner import BLOCK_TIME
from dotenv import load_dotenv
from typing import Optional

load_dotenv()  # take environment variables from .env.
MINER_NODE_URL = environ.get("MINER_NODE") + ':' + environ.get("MINER_PORT")


def wallet():
    response = None
    while response != "5":
        response = input("""What do you want to do?
        1. Generate new wallet
        2. Send coins to another wallet
        3. Check transactions
        4. Print miner logs
        5. Quit\n""")
        if response == "1":
            # Generate new wallet
            print("""=========================================\n
                    IMPORTANT: save this credentials or you won't be able to recover your wallet\n
                    =========================================\n""")
            generate_ecdsa_keys()
        elif response == "2":
            addr_from = input("From: introduce your wallet address (public key)\n")
            private_key = input("Introduce your private key\n")
            addr_to = input("To: introduce destination wallet address\n")
            amount = input("Amount: number stating how much do you want to send\n")
            msg = input("Hidden/Locked Message: the message going to be release in the future\n")
            lock_time = input("Lock Time (sec): time for locking the message")
            print("=========================================\n\n")
            print("Is everything correct?\n")
            print(F"From: {addr_from}\nPrivate Key: {private_key}\nTo: {addr_to}\nAmount: {amount}\n")
            print(f"Message: {msg}\n The message is going to be release after {lock_time} second.")
            response = input("y/n\n")
            if response.lower() == "y":
                try:
                    lock_time_s = int(lock_time)
                    send_transaction(addr_from, private_key, addr_to, amount, msg, lock_time_s)
                except ValueError:
                    print(f"{lock_time} is not a valid input for time release encryption.")

        elif response == "3":
            start = input("The start index of block: (inclusive)\n")
            end = input("The end index of block: (exclusive)\n")
            start = int(start) if len(start) > 0 else None
            end = int(end) if len(end) > 0 else None
            check_transactions(start, end)
        elif response == "4":
            check_logs()


def send_transaction(addr_from, private_key, addr_to, amount, msg=None, lock_time=0):
    """
    Sends your transaction to different nodes. Once any of the nodes manage
    to mine a block, your transaction will be added to the blockchain. Despite
    that, there is a low chance your transaction gets canceled due to other nodes
    having a longer chain. So make sure your transaction is deep into the chain
    before claiming it as approved!

    Args:
        addr_from: send tx from address
        private_key: private key to sign the tx
        addr_to: send tx to address
        amount: amount of token to be sent
        msg: message to be release in the future
        lock_time: time for locking the message before its release

    Returns:

    """
    if len(private_key) == 64:
        # tx ID is omitted instead of using address to query tx data from database
        # for simplification of implementation
        # prepare tx info and signature
        data = {"addr_from": addr_from,
                "addr_to": addr_to,
                "amount": amount,
        }
        tx_json = json.dumps(data, separators=(',', ':'))
        signature = sign_ecdsa_data(private_key, tx_json)
        url = MINER_NODE_URL + '/txion'
        # decode signature bytes into utf-8 string
        data["signature"] = signature.decode()
        headers = {"Content-Type": "application/json"}
        if msg and lock_time > 0:
            # prepare time release encryption
            last_url = MINER_NODE_URL + '/last'
            block_res = requests.get(last_url)
            block_data = block_res.json()
            if block_data["height"] > 0:
                last_block = Block.from_db(block_data)
                # after a number of block, the encrypted message will be released
                block_interval = lock_time//BLOCK_TIME
                future_pub_key = last_block.public_key
                # derive future public key
                for _ in range(block_interval):
                    future_pub_key = elgamal.generate_pub_key(seed=int(future_pub_key.p + future_pub_key.g + future_pub_key.h),
                                                              bit_length=future_pub_key.bit_length)
                # encrypt time release message
                cipher = elgamal.encrypt(future_pub_key, msg)
                data['release_block_idx'] = last_block.height + block_interval
                data['cipher'] = cipher
        res = requests.post(url, json=data, headers=headers)
        print(res.text)
    else:
        print("Wrong address or key length! Verify and try again.")


def check_transactions(start: Optional[int] = None, end: Optional[int] = None):
    """Retrieve the entire blockchain. With this you can check your
    wallets balance. If the blockchain is to long, it may take some time to load.
    """
    blocks_url = MINER_NODE_URL + '/blocks'
    params = {}
    if start:
        params["start"] = start
    if end:
        params["end"] = end
    res = requests.get(blocks_url, params=params)
    print(res.text)


def check_logs():
    """Get the status logs from the miner."""
    logs_url = MINER_NODE_URL + '/logs'
    res = requests.get(logs_url)
    print(res.text)


if __name__ == '__main__':
    print("""       =========================================\n
        SIMPLE COIN v1.0.0 - BLOCKCHAIN SYSTEM\n
       =========================================\n\n
        You can find more help at: https://github.com/cosme12/SimpleCoin\n
        Make sure you are using the latest version or you may end in
        a parallel chain.\n\n\n""")
    wallet()
    input("Press ENTER to exit...")
