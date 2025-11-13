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
