import base64
from flask import Flask, render_template_string, request

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Decrypt Text</title>
</head>
<body>
    <h1>Decrypt Your Text</h1>
    <form method="post">
        <label>Encrypted Text (base64):</label><br>
        <input type="text" name="enc" size="80" value="{{ enc|default('') }}"><br><br>
        <label>Private Key (PEM, containing AES-256 key octets):</label><br>
        <textarea name="key" cols="80" rows="10">{{ key|default('') }}</textarea><br><br>
        <button type="submit">Decrypt</button>
    </form>
    {% if error %}
        <p style="color:red">{{ error }}</p>
    {% endif %}
    {% if result is defined %}
        <h2>Decrypted Text:</h2>
        <pre>{{ result }}</pre>
    {% endif %}
</body>
</html>
'''

def load_aes_key_from_pem(pem_data):
    """
    Loads a raw AES key (octets) from a PEM file.
    Expects PEM file to actually be base64-encoded binary AES key, e.g.:
    -----BEGIN AES PRIVATE KEY-----
    (base64)
    -----END AES PRIVATE KEY-----
    """
    try:
        key = serialization.load_pem_private_key(
            pem_data.encode('utf-8'), 
            password=None,
            backend=default_backend()
        )
        # If the PEM contains an actual AES key, it'll be interpreted as a symmetric key
        # This will only work if someone has encoded the AES key material with a PKCS8 wrapper.
        # If pure octets in base64, decode manually as below:
        # Try reading the PEM as base64:
        lines = pem_data.splitlines()
        b64_lines = [line for line in lines if not line.startswith('-----')]
        key_bytes = base64.b64decode(''.join(b64_lines))
        if len(key_bytes) != 32:
            return None
        return key_bytes
    except Exception:
        return None

def decrypt_aes256_cbc(enc_b64, key_pem):
    try:
        key = load_aes_key_from_pem(key_pem)
        if key is None or len(key) != 32:
            return None
        ct = base64.b64decode(enc_b64)
        iv = ct[:16]
        ciphertext = ct[16:]  # assuming IV is prepended
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(padded) + unpadder.finalize()
        return pt.decode('utf-8')
    except Exception as e:
        return None

@app.route('/', methods=['GET', 'POST'])
def index():
    error = None
    result = None
    enc = ''
    key = ''
    if request.method == 'POST':
        enc = request.form.get('enc', '')
        key = request.form.get('key', '')
        if not enc or not key:
            error = "Please provide both encrypted text and private key (PEM)."
        else:
            result = decrypt_aes256_cbc(enc, key)
            if result is None:
                error = "Decryption failed. Ensure PEM contains a 32-byte AES key."
    return render_template_string(HTML_TEMPLATE, error=error, result=result, enc=enc, key=key)

if __name__ == '__main__':
    app.run(debug=True)
