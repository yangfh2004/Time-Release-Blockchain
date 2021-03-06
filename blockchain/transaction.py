

class Tx:
    def __init__(self,
                 addr_from: str,
                 addr_to: str,
                 amount: int,
                 cipher: str = None,
                 release_block: int = 0):
        self.version = 1.0
        self.addr_from = addr_from
        self.addr_to = addr_to
        self.amount = amount
        # time release message
        self.cipher = cipher
        # now only support single release block
        # TODO: support release the message in a range of block
        self.release_block_idx = release_block

    @classmethod
    def from_dict(cls, tx: dict):
        addr_from = tx["addr_from"]
        addr_to = tx["addr_to"]
        amount = tx["amount"]
        if "cipher" in tx and tx["cipher"] is not None and "release_block_idx" in tx and tx["release_block_idx"]:
            cipher = tx["cipher"]
            release_block = tx["release_block_idx"]
            return Tx(addr_from, addr_to, amount, cipher, release_block)
        else:
            return Tx(addr_from, addr_to, amount)

    @classmethod
    def coinbase(cls, miner_address: str, reward: int):
        """
        Coinbase Tx for mining reward.

        Args:
            miner_address: miner's address to receive rewards.
            reward: amount of mining reward.

        Returns:
            Coinbase Tx
        """
        return Tx('network', miner_address, reward)
