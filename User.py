from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64
import csv

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

# Save public keys in 'keys.csv' and private keys in 'pkeys.csv' (PEM format, base64-encoded, just for demo purposes)
with open('keys.csv', 'w', newline='') as pubf, open('pkeys.csv', 'w', newline='') as privf:
    pub_writer = csv.writer(pubf)
    priv_writer = csv.writer(privf)
    # Write header (optional):
    # pub_writer.writerow(['field', 'public_key_base64'])
    # priv_writer.writerow(['field', 'private_key_base64'])

    for label, keys in key_pairs.items():
        # Serialize to PEM
        pub_pem = keys['public_key'].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        priv_pem = keys['private_key'].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        # Base64-encode the PEM for single-line CSV
        pub_b64 = base64.b64encode(pub_pem).decode('utf-8')
        priv_b64 = base64.b64encode(priv_pem).decode('utf-8')
        # Write to respective files
        pub_writer.writerow([label, pub_b64])
        priv_writer.writerow([label, priv_b64])
