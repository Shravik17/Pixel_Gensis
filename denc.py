import json
import base64
import csv
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

class MalformedFramingError(Exception):
    """Custom exception for malformed framing errors."""
    pass

def safe_b64decode(data):
    """Pad base64 string as needed and decode."""
    data = data.strip()
    missing_padding = (4 - len(data) % 4) % 4
    if missing_padding:
        data += "=" * missing_padding
    try:
        return base64.b64decode(data.encode())
    except Exception as e:
        raise MalformedFramingError(f"Malformed base64 framing: {e}")

def add_pem_headers(key_body):
    """
    Wrap base64 PEM key_body with standard PEM headers/footers for PKCS#8 private keys.
    """
    # Group into 64-char lines and surround with headers
    key_body_clean = key_body.replace("\n", "").replace("\r", "")
    pem_lines = [key_body_clean[i:i+64] for i in range(0, len(key_body_clean), 64)]
    pem = "-----BEGIN PRIVATE KEY-----\n"
    pem += "\n".join(pem_lines)
    pem += "\n-----END PRIVATE KEY-----\n"
    return pem

def load_private_keys(pkeys_file):
    # Reads a CSV WITH HEADERS: name,key in each row
    # Each key column contains base64 DER, no PEM header/footer.
    # Returns dict: {name: rsa_private_key_obj OR error string}
    pkeys = {}
    with open(pkeys_file, "r", newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            # Defensive skip: must have at least 'name','key'
            field = row.get("name", "").strip()
            pem_body = row.get("key", "").strip()
            if not field or not pem_body:
                continue
            try:
                pem_clean = add_pem_headers(pem_body)
                private_key = serialization.load_pem_private_key(
                    pem_clean.encode("utf-8"), password=None
                )
                pkeys[field] = private_key
            except Exception as e:
                err_msg = str(e)
                pkeys[field] = f"<Private key load failed: {err_msg}>"
    return pkeys

def decrypt_field(private_key, b64_ciphertext):
    try:
        ciphertext = safe_b64decode(b64_ciphertext)
    except MalformedFramingError as mf:
        return f"<Malformed framing error: {mf}>"
    try:
        decrypted = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode("utf-8")
    except Exception as e:
        return f"<Decryption failed: {e}>"

def decrypt_blockchain(json_file, pkeys_file):
    pkeys = load_private_keys(pkeys_file)
    with open(json_file, "r") as f:
        blocks = json.load(f)

    decrypted_blocks = []

    for block in blocks:
        if isinstance(block.get("data"), dict) and "encrypted_credentials" in block["data"]:
            cred = block["data"]["encrypted_credentials"]
            decrypted_creds = {}
            for field, b64_val in cred.items():
                if field in pkeys and not isinstance(pkeys[field], str):
                    plaintext = decrypt_field(pkeys[field], b64_val)
                    decrypted_creds[field] = plaintext
                elif field in pkeys and isinstance(pkeys[field], str):
                    decrypted_creds[field] = pkeys[field]
                else:
                    decrypted_creds[field] = "<Missing private key>"
            decrypted_data = dict(block["data"])
            decrypted_data["encrypted_credentials"] = decrypted_creds
            block_out = dict(block)
            block_out["data"] = decrypted_data
            decrypted_blocks.append(block_out)
        else:
            decrypted_blocks.append(block)

    print(json.dumps(decrypted_blocks, indent=2))

if __name__ == "__main__":
    decrypt_blockchain("blockchain.json", "pkeys.csv")
