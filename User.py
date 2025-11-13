from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate 3 key pairs: one for name, one for age, one for aadhar
key_pairs = {}

for label in ['name', 'age', 'aadhar']:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    key_pairs[label] = {
        'private_key': private_key,
        'public_key': public_key,
    }
for label, keys in key_pairs.items():
    print(f"Label: {label}")
    priv_pem = keys['private_key'].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = keys['public_key'].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("Private Key:")
    print(priv_pem.decode('utf-8'))
    print("Public Key:")
    print(pub_pem.decode('utf-8'))
    print("------")
