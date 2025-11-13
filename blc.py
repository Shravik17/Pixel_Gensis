import hashlib
import json
from datetime import datetime

import csv
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

class Block:
    """Single block in the blockchain"""

    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Calculate SHA-256 hash of block"""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": str(self.timestamp),
            "data": self.data,
            "previous_hash": self.previous_hash
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def __str__(self):
        return f"Block #{self.index} | Hash: {self.hash[:16]}..."


class IdentityBlockchain:
    """Blockchain for storing identity credential hashes"""

    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        """Create the first block"""
        genesis = Block(0, datetime.now(), "Genesis Block", "0")
        self.chain.append(genesis)
        print("✓ Genesis block created")
    
    def get_latest_block(self):
        """Get the most recent block"""
        return self.chain[-1]

    def add_identity_block(self, user_id, encrypted_credentials):
        """Add a new identity block to the chain"""
        # Create hash of encrypted credentials
        credential_hash = hashlib.sha256(
            json.dumps(encrypted_credentials, sort_keys=True).encode()
        ).hexdigest()

        # Store the full encrypted fields in the block (not just hashes)
        data = {
            "user_id": user_id,
            "encrypted_credentials": encrypted_credentials,
            "credential_hash": credential_hash,
            "timestamp": str(datetime.now())
        }

        # Create new block
        new_block = Block(
            index=len(self.chain),
            timestamp=datetime.now(),
            data=data,
            previous_hash=self.get_latest_block().hash
        )

        self.chain.append(new_block)
        print(f"✓ Block #{new_block.index} added for user: {user_id}")
        return new_block

    def verify_chain(self):
        """Verify blockchain integrity"""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]

            # Check if current hash is correct
            if current.hash != current.calculate_hash():
                return False, f"Block #{i} has been tampered with!"

            # Check if previous hash matches
            if current.previous_hash != previous.hash:
                return False, f"Block #{i} chain is broken!"

        return True, "Blockchain is valid!"

    def get_user_identity(self, user_id):
        """Retrieve user's identity block from blockchain"""
        for block in self.chain[1:]:  # Skip genesis
            if block.data.get("user_id") == user_id:
                return block
        return None

    def display_chain(self):
        """Display entire blockchain"""
        print("\n" + "="*70)
        print("IDENTITY BLOCKCHAIN")
        print("="*70)

        for block in self.chain:
            print(f"\nBlock #{block.index}")
            print(f"  Timestamp: {block.timestamp}")
            print(f"  Data: {block.data}")
            print(f"  Hash: {block.hash}")
            print(f"  Previous: {block.previous_hash}")
            print("-"*70)


def load_public_keys_from_csv(csv_path, fields):
    """
    Load public keys for each field from a CSV file.

    CSV structure: field_name, public_key_base64 (PEM or DER base64 encoded)
    """
    public_keys = {}
    with open(csv_path, "r", newline="") as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if len(row) != 2:
                continue
            field_name = row[0].strip()
            key_b64 = row[1].strip()
            if field_name in fields:
                pem = base64.b64decode(key_b64.encode('utf-8'))
                public_key = serialization.load_pem_public_key(pem, backend=default_backend())
                public_keys[field_name] = public_key
    # Confirm all fields present
    for f in fields:
        if f not in public_keys:
            raise ValueError(f"Public key for field '{f}' not found in CSV")
    return public_keys


class CredentialVault:
    """Decentralized Digital Identity Vault with Blockchain and external provided keys"""

    FIELD_NAMES = ['name', 'age', 'aadhar']

    def __init__(self, blockchain, csv_keyfile):
        self.blockchain = blockchain
        # Load public keys for each field from provided csv file
        self.public_keys = load_public_keys_from_csv(csv_keyfile, self.FIELD_NAMES)
        self.encrypted_vault = {}
        self.user_id = None

    def _encrypt_data(self, data, public_key):
        data_bytes = str(data).encode('utf-8')
        encrypted = public_key.encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode('utf-8')

    def register_identity(self, user_id, name, age, aadhar):
        """Encrypt each credential field using public keys from csv and store on blockchain"""
        self.user_id = user_id

        # Encrypt credentials with the provided public keys
        self.encrypted_vault = {
            'name': self._encrypt_data(name, self.public_keys['name']),
            'age': self._encrypt_data(age, self.public_keys['age']),
            'aadhar': self._encrypt_data(aadhar, self.public_keys['aadhar'])
        }

        # Add to blockchain
        block = self.blockchain.add_identity_block(user_id, self.encrypted_vault)

        print(f"✓ Identity registered on blockchain!")
        return block

    # Note: We can't decrypt without the private keys which are not available here
    def get_encrypted_credential(self, field_name):
        """Retrieve an encrypted credential"""
        return self.encrypted_vault.get(field_name)


# Demo
if __name__ == "__main__":
    print("🔗 BLOCKCHAIN-BASED IDENTITY VAULT (with keys from CSV)\n")

    # Path to CSV file with fields and public keys (in PEM base64)
    CSV_KEYFILE = "keys.csv"  # <-- Place your CSV file here with name,age,aadhar public keys

    if not os.path.exists(CSV_KEYFILE):
        raise FileNotFoundError(f"CSV key file '{CSV_KEYFILE}' not found. " 
                                f"Place your key file in the working directory.")

    # Create blockchain
    blockchain = IdentityBlockchain()

    # Create vault using public keys from CSV
    vault = CredentialVault(blockchain, CSV_KEYFILE)

    # Register identity
    print("\n📝 Registering identity...")
    vault.register_identity(
        user_id="USER001",
        name="vaish",
        age=19,
        aadhar="1234-5678-9012"
    )

    # Verify blockchain
    print("\n🔍 Verifying blockchain...")
    valid, message = blockchain.verify_chain()
    print(f"  {message}")

    # Display blockchain (showing encrypted values)
    blockchain.display_chain()
