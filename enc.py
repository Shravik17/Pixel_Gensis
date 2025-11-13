from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
import json

class CredentialVault:
    """Decentralized Digital Identity and Credentials Vault"""
    
    def __init__(self):
        # Generate separate key pairs for each credential
        self.name_keys = self._generate_key_pair()
        self.age_keys = self._generate_key_pair()
        self.aadhar_keys = self._generate_key_pair()
        
        # Store encrypted data
        self.encrypted_vault = {}
    
    def _generate_key_pair(self):
        """Generate RSA public/private key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        return {
            'private': private_key,
            'public': public_key
        }
    
    def _encrypt_data(self, data, public_key):
        """Encrypt data using RSA public key"""
        # Convert data to bytes
        data_bytes = str(data).encode('utf-8')
        
        # Encrypt using public key
        encrypted = public_key.encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Return base64 encoded string for easy storage
        return base64.b64encode(encrypted).decode('utf-8')
    
    def _decrypt_data(self, encrypted_data, private_key):
        """Decrypt data using RSA private key"""
        # Decode from base64
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Decrypt using private key
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted.decode('utf-8')
    
    def encrypt_credentials(self, name, age, aadhar):
        """Encrypt all credentials with their respective key pairs"""
        self.encrypted_vault['name'] = self._encrypt_data(name, self.name_keys['public'])
        self.encrypted_vault['age'] = self._encrypt_data(age, self.age_keys['public'])
        self.encrypted_vault['aadhar'] = self._encrypt_data(aadhar, self.aadhar_keys['public'])
        
        print("✓ All credentials encrypted successfully!")
        return self.encrypted_vault
    
    def decrypt_credential(self, field_name):
        """Decrypt a specific credential using its private key"""
        if field_name not in self.encrypted_vault:
            return f"Error: {field_name} not found in vault"
        
        key_map = {
            'name': self.name_keys,
            'age': self.age_keys,
            'aadhar': self.aadhar_keys
        }
        
        if field_name not in key_map:
            return "Error: Invalid field name"
        
        encrypted_data = self.encrypted_vault[field_name]
        decrypted_data = self._decrypt_data(encrypted_data, key_map[field_name]['private'])
        
        return decrypted_data
    
    def export_public_keys(self):
        """Export public keys in PEM format for sharing"""
        public_keys = {}
        
        for field, keys in [('name', self.name_keys), 
                           ('age', self.age_keys), 
                           ('aadhar', self.aadhar_keys)]:
            pem = keys['public'].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            public_keys[field] = pem.decode('utf-8')
        
        return public_keys
    
    def display_vault_status(self):
        """Display current vault status"""
        print("\n" + "="*60)
        print("DIGITAL IDENTITY VAULT STATUS")
        print("="*60)
        
        for field in ['name', 'age', 'aadhar']:
            status = "✓ Encrypted" if field in self.encrypted_vault else "✗ Not encrypted"
            print(f"{field.capitalize():10} : {status}")
            if field in self.encrypted_vault:
                preview = self.encrypted_vault[field][:40] + "..."
                print(f"{'':10}   Preview: {preview}")
        
        print("="*60 + "\n")


# Demo Usage
if __name__ == "__main__":
    print("🔐 Decentralized Digital Identity Vault Demo\n")
    
    # Create vault instance
    vault = CredentialVault()
    
    # Sample identity data
    user_name = "vaish"
    user_age = 19
    user_aadhar = "1234-5678-9012"
    
    print("Original Credentials:")
    print(f"  Name   : {user_name}")
    print(f"  Age    : {user_age}")
    print(f"  Aadhar : {user_aadhar}\n")
    
    # Encrypt credentials
    print("Encrypting credentials with separate key pairs...")
    vault.encrypt_credentials(user_name, user_age, user_aadhar)
    
    # Display vault status
    vault.display_vault_status()
    
    # Demonstrate decryption
    print("Decrypting individual credentials:\n")
    
    decrypted_name = vault.decrypt_credential('name')
    print(f"  Decrypted Name   : {decrypted_name}")
    
    decrypted_age = vault.decrypt_credential('age')
    print(f"  Decrypted Age    : {decrypted_age}")
    
    decrypted_aadhar = vault.decrypt_credential('aadhar')
    print(f"  Decrypted Aadhar : {decrypted_aadhar}")
    
    # Export public keys
    print("\n\nPublic Keys (shareable):")
    print("-" * 60)
    public_keys = vault.export_public_keys()
    for field, key in public_keys.items():
        print(f"\n{field.upper()} Public Key:")
        print(key)
