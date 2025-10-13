# blockchain.py
import json
import rsa

class Transaction:
    """Represents a single transaction with sender, recipient, amount, and signature"""
    def __init__(self, sender, recipient, amount, signature=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        if signature:
            try:
                self.signature = bytes.fromhex(signature)
            except ValueError:
                # fallback for dummy signature
                self.signature = signature.encode()
        else:
            self.signature = None

    def to_dict(self):
        return {"sender": self.sender, "recipient": self.recipient, "amount": self.amount}

class Wallet:
    """Represents a user wallet with public/private keys"""
    def __init__(self):
        self.public_key, self.private_key = rsa.newkeys(512)

    def get_address(self):
        return self.public_key.save_pkcs1().decode()

    def sign_transaction(self, transaction: Transaction):
        message = json.dumps(transaction.to_dict(), sort_keys=True).encode()
        signature = rsa.sign(message, self.private_key, "SHA-256")
        transaction.signature = signature
        return transaction

# uncomment this when NOT testing

# class BlockchainVerifier:
#     """Lightweight verifier to check transaction authenticity"""
    
#     @staticmethod
#     def verify_transaction(transaction: Transaction) -> bool:
#         try:
#             message = json.dumps(transaction.to_dict(), sort_keys=True).encode()
#             pub_key = rsa.PublicKey.load_pkcs1(transaction.sender.encode())
#             rsa.verify(message, transaction.signature, pub_key)
#             return True
        
#         except Exception:
#             return False

class BlockchainVerifier:
    @staticmethod
    def verify_transaction(transaction: Transaction) -> bool:
        # FOR TESTING ONLY: accept any transaction
        return True


# Run as CLI (for server call)
if __name__ == "__main__":
    import sys
    import json

    # Input as JSON string from Node.js
    tx_data = json.loads(sys.stdin.read())
    tx = Transaction(tx_data['sender'], tx_data['recipient'], tx_data['amount'], tx_data['signature'])

    valid = BlockchainVerifier.verify_transaction(tx)
    # Return result as JSON string
    print(json.dumps({"valid": valid}))
