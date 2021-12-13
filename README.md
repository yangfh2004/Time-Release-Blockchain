# Time-Release Blockchain and Application
This project was a fork from [Sangoou's project](https://github.com/Sangoou/BlockchainEVote).

This project is based on a simplified PoW blockchain with some modification to fit modern Python 3.9
    - [SimpleCoin](https://github.com/cosme12/SimpleCoin) 

In this repo, we aim to provide educational materials to test and learn a new design for time-release blockchain technology.
Moreover, some flaws in existing design would be fixed in our new design.

This is a very simple Python implementation of main ideas for time-release blockchain and its core functionalities.

## Directories
* blockchain - Python modules for Block and Transaction classes using in this blockchain.
* crypto - Discrete Log Problem Based Crypto system (e.g. elgamal) implementation in Python for 
  encryption and decryption of data
* mining - Mining module which provide time-release functionality and blockchain PoW mining work
* test - Test codes

## Files in Root Dir

- miner_config.py - default configuration settings for current miner, you may add your customize configurations
- miner.py - the core miner code to run
- .env - the environmental variables to run the blockchain node, including the miner address, miner url & port
and peer nodes url. If using other miner url, you may modify this file locally.
- wallet.py - the core wallet code for sending and receiving tokens for this blockchain
  - if you run the wallet.py, it may generate a public key and private key for transaction as stored in the "test_miner.txt"
  file. Note that this key pair is based on ECDSA which is only for transaction but not time-release data encryption.
- app.py - the Flask app to provide web service  between miner nodes and frontend wallet.
if running the Flask app with a customized node ip and port, please use below shell script.
```shell
    python3 -m flask run --host=127.0.0.1 --port=5000
   ```
