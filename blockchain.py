import hashlib
import json
import time
from typing import List
import sys
from web3 import Web3
import os
from pymongo import MongoClient  # Added for broadcast flag check

class Transaction:
    def __init__(self, sender, recipient, amount, signature):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = signature

    def to_dict(self):
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "signature": self.signature
        }

class Block:
    def __init__(self, index, transactions: List['Transaction'], previous_hash):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [t.to_dict() for t in self.transactions],
            "previous_hash": self.previous_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions: List[Transaction] = []

    def create_genesis_block(self):
        return Block(0, [], "0")

    def get_latest_block(self):
        return self.chain[-1]

    def verify_transaction(self, transaction: 'Transaction'):
        return transaction.signature == "valid_signature"

    def add_transaction(self, transaction: 'Transaction'):
        if not transaction.sender or not transaction.recipient or not transaction.amount:
            raise ValueError("Transaction must include sender, recipient, and amount")
        if not self.verify_transaction(transaction):
            raise ValueError("Transaction verification failed")
        self.pending_transactions.append(transaction)

    def record_transactions(self):
        if not self.pending_transactions:
            return None
        new_block = Block(
            index=len(self.chain),
            transactions=self.pending_transactions,
            previous_hash=self.get_latest_block().hash
        )
        self.chain.append(new_block)
        self.pending_transactions = []
        return new_block


# Ethereum Broadcast Logic
def broadcast_to_ethereum(block_hash, tx_data):
    try:
        some_data = json.loads(sys.stdin.read())
        print(f"🐍 Python received data: {some_data}", file=sys.stderr)

        rpc_url = os.getenv("SEPOLIA_RPC_URL")  # Sepolia RPC (testnet)
        private_key = os.getenv("SEPOLIA_PRIVATE_KEY")

        if not rpc_url or not private_key:
            return {"status": "error", "message": "Missing RPC URL or private key error"}

        web3 = Web3(Web3.HTTPProvider(rpc_url))
        acct = web3.eth.account.from_key(private_key)

        # readable metadata
        metadata = {
            "block_hash": block_hash,
            "sender": tx_data['sender'],
            "recipient": tx_data['recipient'],
            "amount": tx_data['amount'],
            "timestamp": int(time.time())
        }

        metadata_json = json.dumps(metadata)
        data_bytes = web3.to_bytes(text=metadata_json)

        # This builds a zero-value Ethereum transaction that just carries your data:
        tx = {
            'to': acct.address,   # send to self (no real transfer) | transfering to self so we dont loose eth
            'value': 0,           # no ETH moved
            'data': data_bytes,   # visible metadata we created above
            'gas': 120000,        # enough for data payload
            'gasPrice': web3.eth.gas_price,     # fetched from the network
            'nonce': web3.eth.get_transaction_count(acct.address),  # transaction count for your account (avoids duplicates)
            'chainId': 11155111   # Sepolia
        }

        signed_tx = acct.sign_transaction(tx)   # signing our transaction
        tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)

        print(f"✅ Broadcasted to Ethereum: {web3.to_hex(tx_hash)}", file=sys.stderr)
        return {"status": "success", "tx_hash": web3.to_hex(tx_hash)}

    except Exception as e:
        print(f"❌ Broadcast error: {e}", file=sys.stderr)
        return {"status": "error", "message": str(e)}


# Check broadcast flag from MongoDB
def get_broadcast_flag():
    try:
        mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
        client = MongoClient(mongo_uri)
        db = client["mydb"]
        config = db["config"].find_one({}, {"broadcast_enabled": 1, "_id": 0})
        flag = bool(config.get("broadcast_enabled")) if config else False
        print(f"📡 Broadcast flag from DB: {flag}", file=sys.stderr)
        return flag
    except Exception as e:
        print(f"❌ Error checking broadcast flag: {e}", file=sys.stderr)
        return False


if __name__ == "__main__":
    try:
        tx_data = json.loads(sys.stdin.read())
        tx = Transaction(
            sender=tx_data['sender'],
            recipient=tx_data['recipient'],
            amount=tx_data['amount'],
            signature=tx_data['signature']
        )

        blockchain = Blockchain()
        blockchain.add_transaction(tx)
        new_block = blockchain.record_transactions()

        block_hash = new_block.hash if new_block else blockchain.get_latest_block().hash

        # Check MongoDB flag before broadcasting
        if get_broadcast_flag():
            print("🟢 Broadcast enabled — sending to Ethereum...", file=sys.stderr)
            eth_result = broadcast_to_ethereum(block_hash, tx_data)
        else:
            print("🟠 Broadcast disabled — skipping Ethereum broadcast.", file=sys.stderr)
            eth_result = {"status": "skipped", "tx_hash": None}

        output = {
            "valid": True,
            "block_hash": block_hash,
            "ethereum_status": eth_result["status"],
            "ethereum_tx": eth_result.get("tx_hash", None),
            "ethereum_error": eth_result.get("message", None)
        }

        print(json.dumps(output))

    except Exception as e:
        print(f"🔥 Fatal error: {e}", file=sys.stderr)
        print(json.dumps({"valid": False, "error": str(e)}))
