# Simple Time Release Blockchain Core
This is a very simple Python implementation of main ideas for time-release blockchain and its core functionalities.

## Directories
* crypto - Discrete Log Problem Based Crypto system (e.g. elgamal) implementation in Python for 
  encryption and decryption of data
  
* test - Test codes

## Files in Root Dir

- default_miner_config.json - default configuration settings for current miner, you may add your customize configurations
- miner.py - the core miner code to run
    - optional argument '-c' or '--config' for your custom miner config json file. For example, if you have a config file
  named as "custom_miner_config.json", you may use below command to run with it.
    ```shell
    python3 miner.py -c custom_miner_config.json
    ```
- wallet.py - the core wallet code for sending and receiving tokens for this blockchain
  - if you run the wallet.py, it may generate a public key and private key for transaction as stored in the "test_miner.txt"
  file. Note that this key pair is based on ECDSA which is only for transaction but not time-release data encryption.