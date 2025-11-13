from flask import Flask, request, jsonify
from flask_cors import CORS
app = Flask(_name_)
CORS(app)
users = {} 
@app.route('/api/test')
def test():
    return jsonify({'message': 'Backend running'})
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'success': False, 'message': 'username and password required.'}), 400

    if username in users:
        return jsonify({'success': False, 'message': 'username already exists.'}), 400

    users[username] = password
    return jsonify({'success': True, 'message': f'User {username} registered successfully!'})
if _name_ == '_main_':
    app.run(debug=True)