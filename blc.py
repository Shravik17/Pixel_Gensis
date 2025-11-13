import hashlib
import json
from datetime import datetime

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
        
        # Create block data
        data = {
            "user_id": user_id,
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


# Integration with CredentialVault
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

class CredentialVault:
    """Decentralized Digital Identity Vault with Blockchain"""
    
    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.name_keys = self._generate_key_pair()
        self.age_keys = self._generate_key_pair()
        self.aadhar_keys = self._generate_key_pair()
        self.encrypted_vault = {}
        self.user_id = None
    
    def _generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        return {'private': private_key, 'public': private_key.public_key()}
    
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
    
    def _decrypt_data(self, encrypted_data, private_key):
        encrypted_bytes = base64.b64decode(encrypted_data)
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode('utf-8')
    
    def register_identity(self, user_id, name, age, aadhar):
        """Encrypt credentials and store on blockchain"""
        self.user_id = user_id
        
        # Encrypt credentials
        self.encrypted_vault = {
            'name': self._encrypt_data(name, self.name_keys['public']),
            'age': self._encrypt_data(age, self.age_keys['public']),
            'aadhar': self._encrypt_data(aadhar, self.aadhar_keys['public'])
        }
        
        # Add to blockchain
        block = self.blockchain.add_identity_block(user_id, self.encrypted_vault)
        
        print(f"✓ Identity registered on blockchain!")
        return block
    
    def decrypt_credential(self, field_name):
        """Decrypt a specific credential"""
        key_map = {
            'name': self.name_keys,
            'age': self.age_keys,
            'aadhar': self.aadhar_keys
        }
        
        if field_name in self.encrypted_vault and field_name in key_map:
            return self._decrypt_data(
                self.encrypted_vault[field_name], 
                key_map[field_name]['private']
            )
        return None


# Demo
if __name__ == "__main__":
    print("🔗 BLOCKCHAIN-BASED IDENTITY VAULT\n")
    
    # Create blockchain
    blockchain = IdentityBlockchain()
    
    # Create vault
    vault = CredentialVault(blockchain)
    
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
    
    # Display blockchain
    blockchain.display_chain()
    
    # Decrypt credentials
    print("\n🔓 Decrypting credentials:")
    print(f"  Name: {vault.decrypt_credential('name')}")
    print(f"  Age: {vault.decrypt_credential('age')}")
    print(f"  Aadhar: {vault.decrypt_credential('aadhar')}")
