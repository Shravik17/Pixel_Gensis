import hashlib
import json
from datetime import datetime
import csv
import smtplib
import random
from email.mime.text import MIMEText
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

from flask import Flask, render_template_string, request, redirect, url_for, flash, session, send_file, make_response
from io import BytesIO, StringIO

HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>MinchiLocker - Blockchain Identity Vault</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      body { font-family: 'Segoe UI',T Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg,#d4f1e8 0%,#a8e6cf 100%); min-height: 100vh; padding: 20px;}
      .container { max-width: 850px; margin: 0 auto; background: #fff; border-radius: 14px; padding: 2em 2.5em 2em 2.5em; box-shadow:0 10px 40px rgba(0,0,0,0.14);}
      header { text-align: center; margin-bottom: 35px;}
      .mint-leaf {font-size: 4em;}
      header h1 { font-size: 2.3em; margin-bottom: 6px;}
      header p { opacity: 0.8; margin-bottom: 6px;}
      h2 {margin-top: 0; margin-bottom: 1.2em; color:#5d4037;}
      .modes {display: flex; justify-content: center; gap: 24px; margin-bottom: 18px;}
      .mode-btn {padding: 12px 32px; border-radius:25px; border:2px solid #5d4037; color:#5d4037; background:rgba(93,64,55,0.08); font-size:1.1em; font-weight: 600; cursor: pointer;}
      .mode-btn.active, .mode-btn:focus {background: #5d4037; color: #fff; border-color:#5d4037;}
      form { max-width: 480px; margin: 0 auto; }
      .form-group {margin-bottom: 22px;}
      label { display: block; font-weight: 600; margin-bottom: 7px;}
      input[type="text"], input[type="password"], input[type="number"] { width: 100%; border-radius:8px; border:2px solid #ddd; padding: 12px 13px; font-size: 1em;}
      button[type="submit"], .auth-btn {background:linear-gradient(135deg,#5d4037 0%, #3d2817 100%); color:#fff; font-weight:600; border: none; border-radius: 30px; padding: 13px 40px; margin-top:16px; font-size:1.1em;}
      .output-box {background:#eafbee; padding:1em 1.5em; margin-top:32px; border-left:5px solid #5d4037; border-radius:7px;}
      .success-msg, .error-msg {margin-bottom:18px;border-radius:8px;padding:9px 16px;font-size:1em;}
      .success-msg {background:#e8f5e9;color:#2e7d32;border-left:4px solid #2e7d32;}
      .error-msg {background:#ffebee;color:#d32f2f;border-left:4px solid #d32f2f;}
      .logout { color: #2e7d32; font-weight:600; text-decoration: none; }
      .toggle-auth { margin: 23px auto 0 auto; text-align: center; color: #5d4037; }
      .toggle-auth a { text-decoration: underline; color: #5d4037; font-weight:600; cursor:pointer;}
      .toggle-auth a:hover { color:#3d2817;}
      .file-link {margin:8px 0 0 0; display:block;}
      @media (max-width: 600px) { .container {padding: .8em;} }
    </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="mint-leaf">🌿</div>
      <h1>MinchiLocker</h1>
      <p>Blockchain-based Secure, Private, and Self-Sovereign Data Ownership</p>
    </header>
    <div class="modes">
      <a href="{{ url_for('index', mode='user') }}" class="mode-btn {% if mode == 'user' %}active{% endif %}">User</a>
      <a href="{{ url_for('index', mode='institution') }}" class="mode-btn {% if mode == 'institution' %}active{% endif %}">Institution</a>
      <a href="{{ url_for('index', mode='view') }}" class="mode-btn {% if mode == 'view' %}active{% endif %}">Blockchain View</a>
      <a href="{{ url_for('index', mode='verifier') }}" class="mode-btn {% if mode == 'verifier' %}active{% endif %}">Verifiers</a>
    </div>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
        <div class="{{ category }}-msg">{{ message }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}
    {% if mode == 'user' %}
      <h2>User Portal</h2>
      {# Removed registration fields and button below as per instructions #}
      <form method="post" action="{{ url_for('generate_keys') }}" style="margin-top:24px;">
        <button type="submit">Generate Public/Private Key Pairs</button>
      </form>
      {% if keygen_success %}
        <div class="output-box" style="margin-top:20px;">
          <h4>✓ Key pairs generated!</h4>
          <span>You can now download your keys:</span>
          <div>
            <a class="file-link" href="{{ url_for('download_keys', key_type='public') }}">⬇️ Download Public Keys (keys.csv)</a>
            <a class="file-link" href="{{ url_for('download_keys', key_type='private') }}">⬇️ Download Private Keys (pkeys.csv)</a>
          </div>
        </div>
      {% endif %}
      {% if registered %}
      <div class="output-box">
        <h4>✓ Encrypted credentials registered on blockchain.</h4>
        <strong>Encrypted Vault (Base64 fields):</strong>
        <pre style="font-size:0.99em;">{{ vault.encrypted_vault | tojson(indent=2) }}</pre>
      </div>
      {% endif %}
    {% elif mode == 'institution' %}
        {# --- OTP EMAIL VERIFICATION UI ADDED --- #}
        {% if not session.get('institution_otp_verified') %}
            <h2>Institution OTP Verification</h2>
            {% if not session.get('institution_otp_sent') %}
                <form method="post" action="{{ url_for('send_institution_otp') }}">
                    <div class="form-group">
                        <label for="institution_email">Enter your institution email address</label>
                        <input type="text" name="institution_email" id="institution_email" required>
                    </div>
                    <button type="submit">Send OTP</button>
                </form>
            {% else %}
                <form method="post" action="{{ url_for('verify_institution_otp') }}">
                    <div class="form-group">
                        <label for="institution_otp">Enter the OTP sent to your email</label>
                        <input type="text" name="institution_otp" id="institution_otp" required>
                    </div>
                    <button type="submit">Verify OTP</button>
                </form>
            {% endif %}
        {% else %}
          <h2>Institution Portal</h2>
          <form method="post" action="{{ url_for('institution_register') }}" enctype="multipart/form-data">
            <div class="form-group">
              <label for="inst_name">Name</label>
              <input type="text" name="inst_name" id="inst_name" required>
            </div>
            <div class="form-group">
              <label for="inst_age">Age</label>
              <input type="number" name="inst_age" id="inst_age" required>
            </div>
            <div class="form-group">
              <label for="inst_aadhar">Aadhar Number</label>
              <input type="text" name="inst_aadhar" id="inst_aadhar" required>
            </div>
            <div class="form-group">
              <label for="keys_file">Upload keys.csv (Public Keys)</label>
              <input type="file" name="keys_file" id="keys_file" accept=".csv" required>
            </div>
            <button type="submit">Register Identity (Institution)</button>
          </form>
          <form method="get" action="{{ url_for('verify_chain') }}" style="margin-top:20px;">
            <button type="submit">Verify Blockchain</button>
          </form>
          {% if inst_registered %}
          <div class="output-box">
            <h4>✓ Encrypted credentials registered on blockchain (via Institution).</h4>
            <strong>Encrypted Vault (Base64 fields):</strong>
            <pre style="font-size:0.99em;">{{ inst_vault | tojson(indent=2) }}</pre>
          </div>
          {% endif %}
          {% if result_checked %}
            <div class="output-box"><strong>{{ result_msg }}</strong></div>
          {% endif %}
        {% endif %}
    {% elif mode == 'view' %}
      <h2>Blockchain: All Registered Identities</h2>
      <div style="max-height: 400px; overflow:auto;">
        {% for block in chain %}
          <div class="output-box" style="margin-top:17px; font-size:0.98em;">
            <div style="font-weight:600;">Block #{{ block['index'] }} <span style="color:#bbb; font-size:0.95em">({% if block['index'] == 0 %}Genesis{% else %}Credential{% endif %})</span></div>
            <strong style="color:#333;">Time:</strong> {{ block['timestamp'] }}<br>
            <strong style="color:#333;">Hash:</strong> <span style="font-family:monospace;">{{ block['hash'][:16] }}...</span><br>
            <strong style="color:#333;">Prev:</strong> <span style="font-family:monospace;">{{ block['previous_hash'][:16] }}...</span>
            {% if block['index'] != 0 %}
              <pre style="background:#fff;margin:7px 0 0 0;padding:8px 9px;border-radius:5px;overflow:auto;">{{ block['data']|tojson(indent=2) }}</pre>
            {% else %}
              <div style="color:#4c6757;">Genesis Block</div>
            {% endif %}
          </div>
        {% endfor %}
      </div>
    {% elif mode == 'verifier' %}
      <h2>Verifier Portal</h2>
      <form method="post" action="{{ url_for('verify_identity') }}" enctype="multipart/form-data">
        <div class="form-group">
          <label for="verify_user_id">User ID</label>
          <input type="text" name="verify_user_id" id="verify_user_id" required>
        </div>
        <div class="form-group">
          <label for="pkeys_file">Upload pkeys.csv (Private Keys)</label>
          <input type="file" name="pkeys_file" id="pkeys_file" accept=".csv" required>
        </div>
        <button type="submit">Search & Decrypt</button>
      </form>
      {% if verified_identity %}
      <div class="output-box">
        <h4>Decrypted Details for User ID: {{ verified_user_id }}</h4>
        <ul style="list-style:none; padding-left:0;">
          <li><strong>Name:</strong> {{ verified_identity.get('name','') }}</li>
          <li><strong>Age:</strong> {{ verified_identity.get('age','') }}</li>
          <li><strong>Aadhar:</strong> {{ verified_identity.get('aadhar','') }}</li>
        </ul>
      </div>
      {% elif verify_error %}
      <div class="output-box error-msg">{{ verify_error }}</div>
      {% endif %}
    {% endif %}
    <div style="margin:40px auto 0 auto;text-align:center;"><small>&copy; 2024 MinchiLocker Blockchain Demo</small></div>
  </div>
</body>
</html>
"""

# --------------------
# Blockchain Classes
# --------------------
class Block:
    """Single block in the blockchain"""
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": str(self.timestamp),
            "data": self.data,
            "previous_hash": self.previous_hash
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
    def __str__(self):
        return f"Block #{self.index} | Hash: {self.hash[:16]}..."
    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": str(self.timestamp),
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }

class IdentityBlockchain:
    """Blockchain for storing identity credential hashes"""
    def __init__(self):
        self.chain = []
        self.create_genesis_block()
    def create_genesis_block(self):
        genesis = Block(0, datetime.now(), "Genesis Block", "0")
        self.chain.append(genesis)
    def get_latest_block(self):
        return self.chain[-1]
    def add_identity_block(self, user_id, encrypted_credentials):
        credential_hash = hashlib.sha256(
            json.dumps(encrypted_credentials, sort_keys=True).encode()
        ).hexdigest()
        data = {
            "user_id": user_id,
            "encrypted_credentials": encrypted_credentials,
            "credential_hash": credential_hash,
            "timestamp": str(datetime.now())
        }
        new_block = Block(
            index=len(self.chain),
            timestamp=datetime.now(),
            data=data,
            previous_hash=self.get_latest_block().hash
        )
        self.chain.append(new_block)
        return new_block
    def verify_chain(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            if current.hash != current.calculate_hash():
                return False, f"Block #{i} has been tampered with!"
            if current.previous_hash != previous.hash:
                return False, f"Block #{i} chain is broken!"
        return True, "Blockchain is valid!"
    def to_json(self):
        return [block.to_dict() for block in self.chain]

# --------------------
# Key Management
# --------------------
def load_public_keys_from_csv_csvfile(csvfile, fields):
    """
    Load public keys from an open CSV file-like object. Format: field_name, public_key_base64
    """
    public_keys = {}
    try:
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
    except Exception as e:
        raise RuntimeError(f"Error loading public keys: {e}")
    for f in fields:
        if f not in public_keys:
            raise ValueError(f"Public key for field '{f}' not found in keys file")
    return public_keys

def load_public_keys_from_csv(csv_path, fields):
    """
    Load public keys from CSV file. Format: field_name, public_key_base64
    """
    public_keys = {}
    try:
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
    except Exception as e:
        raise RuntimeError(f"Error loading public keys: {e}")
    for f in fields:
        if f not in public_keys:
            raise ValueError(f"Public key for field '{f}' not found in CSV")
    return public_keys

def load_private_keys_from_csvfile(csvfile, fields):
    """
    Load private keys from an open CSV file-like object. Format: field_name, private_key_base64
    """
    private_keys = {}
    try:
        reader = csv.reader(csvfile)
        for row in reader:
            if len(row) != 2:
                continue
            field_name = row[0].strip()
            key_b64 = row[1].strip()
            if field_name in fields:
                pem = base64.b64decode(key_b64.encode('utf-8'))
                private_key = serialization.load_pem_private_key(pem, password=None, backend=default_backend())
                private_keys[field_name] = private_key
    except Exception as e:
        raise RuntimeError(f"Error loading private keys: {e}")
    for f in fields:
        if f not in private_keys:
            raise ValueError(f"Private key for field '{f}' not found in pkeys.csv")
    return private_keys

class CredentialVault:
    """Decentralized Digital Identity Vault with Blockchain and external provided keys"""
    FIELD_NAMES = ['name', 'age', 'aadhar']
    def __init__(self, blockchain, csv_keyfile):
        self.blockchain = blockchain
        self.public_keys = load_public_keys_from_csv(csv_keyfile, self.FIELD_NAMES)
        self.encrypted_vault = {}
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
        self.encrypted_vault = {
            'name': self._encrypt_data(name, self.public_keys['name']),
            'age': self._encrypt_data(age, self.public_keys['age']),
            'aadhar': self._encrypt_data(aadhar, self.public_keys['aadhar'])
        }
        block = self.blockchain.add_identity_block(user_id, self.encrypted_vault)
        return block

def institution_register_data(blockchain, name, age, aadhar, csvfile):
    # Helper for the institution form to create the vault and add to blockchain
    FIELD_NAMES = ['name', 'age', 'aadhar']
    public_keys = load_public_keys_from_csv_csvfile(csvfile, FIELD_NAMES)
    encrypted_vault = {}
    for field in FIELD_NAMES:
        data_bytes = str(locals()[field]).encode('utf-8')
        encrypted = public_keys[field].encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_vault[field] = base64.b64encode(encrypted).decode('utf-8')
    # For demonstration we use a random inst_id (could be timestamp+name/sha256...)
    inst_id = "institution_user_" + hashlib.sha256((str(datetime.now())+name+age+aadhar).encode()).hexdigest()[:8]
    block = blockchain.add_identity_block(inst_id, encrypted_vault)
    return block, encrypted_vault

def find_block_by_user_id(blockchain, user_id):
    for blk in blockchain.chain:
        if isinstance(blk.data, dict) and blk.data.get("user_id") == user_id:
            return blk
    return None

def decrypt_identity(encrypted_vault, private_keys):
    FIELD_NAMES = ['name', 'age', 'aadhar']
    result = {}
    for field in FIELD_NAMES:
        enc_val = encrypted_vault.get(field, None)
        if not enc_val:
            result[field] = None
            continue
        try:
            enc_bytes = base64.b64decode(enc_val.encode("utf-8"))
            plain_bytes = private_keys[field].decrypt(
                enc_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            result[field] = plain_bytes.decode("utf-8")
        except Exception as e:
            result[field] = f"DecryptionError: {e}"
    return result

# --------------------
# Flask App
# --------------------
def send_otp_email(receiver_email, otp):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = "shr.otp.verify@gmail.com"
    sender_pass = "qsbu ulor shwf pvkt"
    subject = "Your MinchiLocker OTP Verification Code"
    msg_body = f"Your OTP code for institution login is: {otp}\n\nPlease use this OTP within the next 5 minutes."
    msg = MIMEText(msg_body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_pass)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"OTP sending failed: {e}")
        return False

def create_app():
    app = Flask(__name__)
    app.secret_key = "blockchain-webapp-demo-2024"  # Set to secure value in prod

    # Initialize blockchain
    blockchain = IdentityBlockchain()
    vault = None

    # Default: We'll load keys.csv from CWD at startup (to keep logic identical)
    CSV_KEYFILE = os.environ.get("VAULT_KEYFILE", "keys.csv")
    try:
        vault = CredentialVault(blockchain, CSV_KEYFILE)
    except Exception as e:
        vault = None
        print(f"ERROR: {e}")

    @app.route("/", methods=['GET'])
    def index():
        mode = request.args.get('mode', 'user').lower()

        # If accessing institution page, do not allow unless OTP is verified
        if mode == "institution":
            if not session.get("institution_otp_verified"):
                # Remove any prior registration info so it doesn't appear
                session.pop('inst_registered', None)
                session.pop('inst_vault', None)
                session.pop('result_checked', None)
                session.pop('result_msg', None)

        registered = session.pop('registered', None)
        keygen_success = session.pop('keygen_success', None)
        result_checked = session.pop('result_checked', None)
        result_msg = session.pop('result_msg', None)
        inst_registered = session.pop('inst_registered', None)
        inst_vault = session.pop('inst_vault', None)

        # For verifier UI
        verified_identity = session.pop('verified_identity', None)
        verify_error = session.pop('verify_error', None)
        verified_user_id = session.pop('verified_user_id', None)

        chain = blockchain.to_json() if mode == "view" else []

        # For institution OTP UI rendering in template, ensure keys visible for Jinja
        session.modified = True

        return render_template_string(
            HTML_TEMPLATE,
            mode=mode,
            registered=registered,
            keygen_success=keygen_success,
            vault=vault,
            result_checked=result_checked,
            result_msg=result_msg,
            inst_registered=inst_registered,
            inst_vault=inst_vault,
            chain=chain,
            verified_identity=verified_identity,
            verify_error=verify_error,
            verified_user_id=verified_user_id,
            session=session  # pass session for template logic
        )

    @app.route("/send_institution_otp", methods=['POST'])
    def send_institution_otp():
        email = request.form.get('institution_email', '').strip()
        if not email:
            flash("Email is required.", "error")
            return redirect(url_for('index', mode='institution'))
        otp = "{:06d}".format(random.randint(0, 999999))
        email_sent = send_otp_email(email, otp)
        if not email_sent:
            flash("Failed to send OTP. Please contact admin or try again.", "error")
            return redirect(url_for('index', mode='institution'))
        session['institution_otp'] = otp
        session['institution_email'] = email
        session['institution_otp_sent'] = True
        flash(f"OTP sent to {email}. Please check your inbox/spam!", "success")
        return redirect(url_for('index', mode='institution'))

    @app.route("/verify_institution_otp", methods=['POST'])
    def verify_institution_otp():
        stored_otp = session.get("institution_otp")
        entered_otp = request.form.get("institution_otp", "").strip()
        if not (stored_otp and entered_otp):
            flash("OTP is required.", "error")
            return redirect(url_for('index', mode='institution'))
        if entered_otp == stored_otp:
            session['institution_otp_verified'] = True
            # Clear OTP from session for security
            session.pop('institution_otp')
            session.pop('institution_otp_sent', None)
            flash("OTP verified! Access granted to Institution Portal.", "success")
            return redirect(url_for('index', mode='institution'))
        else:
            flash("Incorrect OTP. Please try again.", "error")
            return redirect(url_for('index', mode='institution'))

    @app.route("/institution_register", methods=['POST'])
    def institution_register():
        # Institution registration accessible only after otp verification
        if not session.get("institution_otp_verified"):
            flash("OTP verification is required to access Institution features.", "error")
            return redirect(url_for('index', mode='institution'))
        name = request.form.get("inst_name", "").strip()
        age = request.form.get("inst_age", "").strip()
        aadhar = request.form.get("inst_aadhar", "").strip()
        keys_file = request.files.get("keys_file")
        if not (name and age and aadhar and keys_file):
            flash("All fields and keys.csv are required.", "error")
            return redirect(url_for('index', mode='institution'))
        try:
            keys_file.stream.seek(0)
            csvfile = StringIO(keys_file.stream.read().decode("utf-8"))
            block, vault_data = institution_register_data(blockchain, name, age, aadhar, csvfile)
            session['inst_registered'] = True
            session['inst_vault'] = vault_data
            flash(f"Identity registered on blockchain via institution.", "success")
        except Exception as e:
            flash(f"Error in institution registration: {str(e)}", "error")
        return redirect(url_for('index', mode='institution'))

    @app.route("/register", methods=['POST'])
    def register_identity():
        if not vault:
            flash("Vault not initialized. Ensure keys.csv is available in the working directory, with 'name', 'age', 'aadhar' public keys.", "error")
            return redirect(url_for('index', mode='user'))
        user_id = request.form.get("user_id").strip()
        name = request.form.get("name").strip()
        age = request.form.get("age").strip()
        aadhar = request.form.get("aadhar").strip()
        if not (user_id and name and age and aadhar):
            flash("All fields required.","error")
            return redirect(url_for('index', mode='user'))
        try:
            vault.register_identity(user_id, name, age, aadhar)
            session['registered'] = True
            flash(f"Identity registered for user: {user_id}", "success")
        except Exception as e:
            flash(f"Error registering identity: {str(e)}", "error")
        return redirect(url_for('index', mode='user'))

    @app.route("/generate_keys", methods=['POST'])
    def generate_keys():
        # Generate keys for 'name', 'age', 'aadhar'
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
        # Save public keys in 'keys.csv' and private keys in 'pkeys.csv' (base64 PEM)
        try:
            with open('keys.csv', 'w', newline='') as pubf, open('pkeys.csv', 'w', newline='') as privf:
                pub_writer = csv.writer(pubf)
                priv_writer = csv.writer(privf)
                for label, keys in key_pairs.items():
                    pub_pem = keys['public_key'].public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    priv_pem = keys['private_key'].private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    pub_b64 = base64.b64encode(pub_pem).decode('utf-8')
                    priv_b64 = base64.b64encode(priv_pem).decode('utf-8')
                    pub_writer.writerow([label, pub_b64])
                    priv_writer.writerow([label, priv_b64])
            flash("Key pairs generated successfully!", "success")
            session['keygen_success'] = True
        except Exception as e:
            flash(f"Error generating keys: {e}", "error")
        return redirect(url_for('index', mode='user'))

    @app.route("/download_keys/<key_type>")
    def download_keys(key_type):
        file_map = {"public": "keys.csv", "private": "pkeys.csv"}
        filename = file_map.get(key_type)
        if not filename or not os.path.exists(filename):
            flash("Requested key file not found. Please generate keys first.", "error")
            return redirect(url_for('index', mode='user'))
        with open(filename, "rb") as f:
            file_bytes = f.read()
        response = make_response(file_bytes)
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

    @app.route("/verify", methods=['GET'])
    def verify_chain():
        # OTP-protect institution verify page also
        if not session.get("institution_otp_verified"):
            flash("OTP verification is required to access Institution features.", "error")
            return redirect(url_for('index', mode='institution'))
        valid, msg = blockchain.verify_chain()
        session['result_checked'] = True
        session['result_msg'] = msg
        flash(msg, "success" if valid else "error")
        return redirect(url_for('index', mode='institution'))

    @app.route("/verify_identity", methods=['POST'])
    def verify_identity():
        verify_user_id = request.form.get("verify_user_id", "").strip()
        file = request.files.get("pkeys_file")
        session['verified_identity'] = None
        session['verify_error'] = None
        session['verified_user_id'] = verify_user_id

        if not verify_user_id or not file:
            session['verify_error'] = "Please provide User ID and upload a valid pkeys.csv"
            return redirect(url_for('index', mode='verifier'))
        try:
            file.stream.seek(0)
            filetext = file.stream.read().decode("utf-8")
            csvfile = StringIO(filetext)
            private_keys = load_private_keys_from_csvfile(csvfile, ['name', 'age', 'aadhar'])

            block = find_block_by_user_id(blockchain, verify_user_id)
            if not block:
                session['verify_error'] = f"User ID '{verify_user_id}' not found on blockchain."
                return redirect(url_for('index', mode='verifier'))
            enc_vault = block.data.get("encrypted_credentials", {})
            decrypted = decrypt_identity(enc_vault, private_keys)
            session['verified_identity'] = decrypted
        except Exception as e:
            session['verify_error'] = f"Error during verification/decryption: {e}"
        return redirect(url_for('index', mode='verifier'))

    return app

if __name__ == "__main__":
    # Remove the startup keys.csv check; allow for key generation at runtime.
    app = create_app()
    app.run(debug=True, port=5000)
