import hashlib
import json
import time
from typing import List
import rsa

class Transaction:
    def __init__(self, sender, recipient, amount, signature=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = signature  # for authentication

    def to_dict(self):
        return {"sender": self.sender, "recipient": self.recipient, "amount": self.amount}

class Block:
    def __init__(self, index, transactions: List[Transaction], previous_hash, timestamp=None, nonce=0):
        self.index = index      # block number in the chain
        self.transactions = transactions    # list of transactions in this block
        self.previous_hash = previous_hash  # hash for previous block
        self.timestamp = timestamp or time.time()   # time when block was creaeted
        self.nonce = nonce      # number adjusted for Proof-of-Work mining
        self.hash = self.calculate_hash()    # unique hash of this block

    def calculate_hash(self):
        # create a unique SHA-256 hash of block content
        block_string = json.dumps({
            "index": self.index,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce
        }, sort_keys=True).encode()

        return hashlib.sha256(block_string).hexdigest()
    
# Blockchain manages the entire chain of blocks
class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]    # list of blocks starting with the genesis block
        self.pending_transactions = []      # transactions waiting to be mined
        self.difficulty = 2     # difficulty for mining (controls PoW complexity)
        self.mining_reward = 100    # reward diven to miner for each block mined

    def create_genesis_block(self):
        # first block of chain with no previous hash
        return Block(0, [], "0")
    
    def get_latest_block(self):
        # return the most recent block in chain
        return self.chain[-1]
    
    def add_transaction(self, transaction: Transaction):
        if not transaction.sender or not transaction.recipient:
            raise Exception("Transaction must include a sender and a recipient")
        
        self.pending_transactions.append(transaction)

    def mine_pending_transactions(self, miner_address):
        # add reward transaction first
        reward_tx = Transaction("System", miner_address, self.mining_reward)
        self.pending_transactions.append(reward_tx)

        # create new block with pending txs
        block = Block(len(self.chain), self.pending_transactions, self.get_latest_block().hash)
        self.proof_of_work(block)
        self.chain.append(block)
        print(f"Block mined: {block.hash}")

        # clear pending transactions after mining
        self.pending_transactions = []


    def proof_of_work(self, block):
        # Keep changing nonce until block hash starts with required number of zeros
        while block.hash[:self.difficulty] != "0" * self.difficulty:
            block.nonce += 1
            block.hash = block.calculate_hash()

    def get_balance(self, address):
        # calculate balance of an address by scanning all transactions in the chain
        balance = 0
        for block in self.chain:
            for tx in block.transactions:

                if tx.sender == address:
                    balance -= tx.amount
                if tx.recipient == address:
                    balance += tx.amount
        return balance
    

# User account with public/private keys
class Wallet:
    def __init__(self):
        self.public_key, self.private_key = rsa.newkeys(512)    # generate rsa key pairs
    
    def get_address(self):
        # public key acts as the wallet address
        return self.public_key.save_pkcs1().decode()
    
    def sign_transaction(self, transaction: Transaction):
        # sign transaction using private key to prove authenticity
        message = json.dumps(transaction.to_dict(), sort_keys=True).encode()
        signature = rsa.sign(message, self.private_key, "SHA-256")
        transaction.signature = signature   # attaching signature to transaction
        return transaction
    

# testing out the code
if __name__ == "__main__":
    blockchain = Blockchain()

    # create wallets
    ak = Wallet()
    ryu = Wallet()
    hime = Wallet()
    miner = Wallet()

    # ak sends 50 coints to ryu
    tx1 = Transaction(ak.get_address(), ryu.get_address(), 50)
    signed_tx = ak.sign_transaction(tx1)    # ak signs it with private key
    blockchain.add_transaction(signed_tx)   # transaction added to pending pool

    # miner mines the pending transaction and gets reward
    blockchain.mine_pending_transactions(miner.get_address())

    print(f"Ak's Balance: {blockchain.get_balance(ak.get_address())}")
    print(f"Ryu's Balance: {blockchain.get_balance(ryu.get_address())}")
    print(f"Miner's Balance: {blockchain.get_balance(miner.get_address())}")