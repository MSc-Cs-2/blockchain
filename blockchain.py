import hashlib
import hmac
import json
import time
from typing import List
import sys
from web3 import Web3
import os
from pymongo import MongoClient  # For fetching/creating secret keys
import secrets  # For generating secret keys if missing

# Represents a single transfer request
class Transaction:
    def __init__(self, sender, recipient, amount, signature, timestamp):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = signature
        self.timestamp = timestamp

    # Converts the transaction into a dictionary for JSON encoding
    def to_dict(self):
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "signature": self.signature,
            "timestamp": self.timestamp
        }

# Represents a single block in the blockchain
# Each block stores:
# - index: its position in chain
# - timestamp: creation time
# - transactions: list of verified transactions
# - previous_hash: hash of the previous block
# - hash: current block’s unique hash (SHA256)
class Block:
    def __init__(self, index, transactions: List['Transaction'], previous_hash):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    # generates a hash for a block (unique)
    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [t.to_dict() for t in self.transactions],
            "previous_hash": self.previous_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

# Handles the entire blockchain logic:
# - Maintains chain of blocks
# - Creates genesis (first) block
# - Verifies transactions using HMAC
# - Adds valid transactions to blocks
# - Records new blocks into chain
class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.pending_transactions: List[Transaction] = []

    def create_genesis_block(self):
        return Block(0, [], "0")

    def get_latest_block(self):
        return self.chain[-1]

    def fetch_or_create_secret_key(self, sender_email):
        """Fetches existing secret from MongoDB or creates one if missing"""
        try:
            mongo_uri = os.getenv("MONGOURI", "mongodb://localhost:27017/")
            client = MongoClient(mongo_uri)
            db = client["Blockchain_Transactions"]
            user = db["secrets"].find_one({"email": sender_email})
            
            if user:
                return user["secretKey"]
            
            # create a new secret key
            new_key = secrets.token_hex(32)
            
            db["secrets"].insert_one({"email": sender_email, "secretKey": new_key})
            print(f"🆕 Secret created for {sender_email}: {new_key}", file=sys.stderr)
            
            return new_key
        
        except Exception as e:
            print(f"❌ Error fetching/creating secret from MongoDB: {e}", file=sys.stderr)
            return None

    # Checks if the transaction’s HMAC signature matches what we calculate using the sender’s secret key
    def verify_transaction(self, transaction: 'Transaction'):
        try:
            secret_key = self.fetch_or_create_secret_key(transaction.sender)

            if not secret_key:
                print(f"❌ No secret key found for {transaction.sender}", file=sys.stderr)
                return False

            # rebuilding the message that was signed
            msg = json.dumps({
                "sender": transaction.sender,
                "recipient": transaction.recipient,
                "amount": transaction.amount,
                "timestamp": transaction.timestamp
            }, sort_keys=True)

            # recalculate the hmac with above message (since this is what we used to create a new hmac)
            calculated_hmac = hmac.new(
                key=secret_key.encode(),
                msg=msg.encode(),
                digestmod=hashlib.sha256
            ).hexdigest() # hexdigest() gives the hash output as a readable hexadecimal string.

            # print(f"🟢 Debug: Calculated HMAC: {calculated_hmac}", file=sys.stderr)
            return calculated_hmac == transaction.signature # now we compare the original hash with the one we created just now to check if it matches

        except Exception as e:
            print(f"❌ HMAC verification error: {e}", file=sys.stderr)
            return False

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
        print(f"🐍 Python received data: {tx_data}", file=sys.stderr)

        rpc_url = os.getenv("SEPOLIA_RPC_URL")  # Sepolia RPC (testnet)
        private_key = os.getenv("SEPOLIA_PRIVATE_KEY")

        if not rpc_url or not private_key:
            return {"status": "error", "message": "Missing RPC URL or private key error"}

        web3 = Web3(Web3.HTTPProvider(rpc_url))
        acct = web3.eth.account.from_key(private_key)

        metadata = {
            "block_hash": block_hash,
            "sender": tx_data['sender'],
            "recipient": tx_data['recipient'],
            "amount": tx_data['amount'],
            "timestamp": int(time.time())
        }

        metadata_json = json.dumps(metadata)
        data_bytes = web3.to_bytes(text=metadata_json)

        tx = {
            'to': acct.address,
            'value': 0,
            'data': data_bytes,
            'gas': 120000,
            'gasPrice': web3.eth.gas_price,
            'nonce': web3.eth.get_transaction_count(acct.address),
            'chainId': 11155111
        }

        signed_tx = acct.sign_transaction(tx)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)

        print(f"✅ Broadcasted to Ethereum: {web3.to_hex(tx_hash)}", file=sys.stderr)
        return {"status": "success", "tx_hash": web3.to_hex(tx_hash)}

    except Exception as e:
        print(f"❌ Broadcast error: {e}", file=sys.stderr)
        return {"status": "error", "message": str(e)}


if __name__ == "__main__":
    try:
        # reading the data we got from our server
        tx_data = json.loads(sys.stdin.read())

        sender = tx_data['sender']
        recipient = tx_data['recipient']
        amount = tx_data['amount']
        timestamp = tx_data.get('timestamp', int(time.time()))
        broadcast_flag = tx_data.get('broadcastToEthereum', False)

        # Step 1: Fetch or create secret key
        blockchain = Blockchain()
        secret_key = blockchain.fetch_or_create_secret_key(sender)

        # Step 2: Generate HMAC signature for transaction
        msg = json.dumps({
            "sender": sender,
            "recipient": recipient,
            "amount": amount,
            "timestamp": timestamp
        }, sort_keys=True)
        
        signature = hmac.new(
            key=secret_key.encode(),
            msg=msg.encode(),
            digestmod=hashlib.sha256
        ).hexdigest()
        
        tx_data['signature'] = signature
        tx_data['timestamp'] = timestamp  # ensure timestamp is included

        # Step 3: Create Transaction object and add to blockchain
        tx = Transaction(sender, recipient, amount, signature, timestamp)
        blockchain.add_transaction(tx)
        new_block = blockchain.record_transactions()
        block_hash = new_block.hash if new_block else blockchain.get_latest_block().hash

        # Step 4: Broadcast to Ethereum if flag from frontend is True
        if broadcast_flag:
            print("🟢 Broadcast enabled — sending to Ethereum...", file=sys.stderr)
            eth_result = broadcast_to_ethereum(block_hash, tx_data)
        else:
            print("🟠 Broadcast disabled — skipping Ethereum broadcast.", file=sys.stderr)
            eth_result = {"status": "skipped", "tx_hash": None}

        # Step 5: Return full transaction info (Node.js handles PayPal & logging)
        output = {
            "valid": True,
            "secret_key": secret_key,
            "signature": signature,
            "block_hash": block_hash,
            "ethereum_status": eth_result["status"],
            "ethereum_tx": eth_result.get("tx_hash", None),
            "ethereum_error": eth_result.get("message", None)
        }

        print(json.dumps(output))

    except Exception as e:
        print(f"🔥 Fatal error: {e}", file=sys.stderr)
        print(json.dumps({"valid": False, "error": str(e)}))
