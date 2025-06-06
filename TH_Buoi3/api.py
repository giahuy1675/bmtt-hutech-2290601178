
from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
from cipher.ecc import ECCCipher

app = Flask(__name__)



ecc_cipher = ECCCipher()

@app.route('/api/ecc/generate_keys', methods=['GET'])
def ecc_generate_keys():
    ecc_cipher.generate_keys()
    return jsonify({'message': 'Keys generated successfully'})

@app.route('/api/ecc/sign', methods=['POST'])
def ecc_sign_message():
    data = request.json
    message = data['message']
    private_key, _ = ecc_cipher.load_keys()
    signature = ecc_cipher.sign(message, private_key)
    signature_hex = signature.hex()
    return jsonify({'signature': signature_hex})

@app.route('/api/ecc/verify', methods=['POST'])
def ecc_verify_signature():
    data = request.json
    message = data['message']
    signature_hex = data['signature']
    public_key, _ = ecc_cipher.load_keys()
    signature = bytes.fromhex(signature_hex)
    is_verified = ecc_cipher.verify(message, signature, public_key)
    return jsonify({'is_verified': is_verified})

# RSA CIPHER ALGORITHM
rsa_cipher = None

@app.route('/api/rsa/generate_keys', methods=['GET'])
def rsa_generate_keys():
    global rsa_cipher
    rsa_cipher = RSA.generate(2048)
    return jsonify({'message': 'Keys generated successfully'})

@app.route('/api/rsa/encrypt', methods=['POST'])
def rsa_encrypt():
    try:
        data = request.get_json()
        message = data['message']
        key_type = data['key_type']
        
        if rsa_cipher is None:
            return jsonify({'error': 'Keys not generated yet'}), 400
        
        # Load appropriate key
        if key_type == 'public':
            key = rsa_cipher.publickey()
        elif key_type == 'private':
            key = rsa_cipher
        else:
            return jsonify({'error': 'Invalid key type'}), 400
        
        # Encrypt message
        cipher = PKCS1_OAEP.new(key)
        encrypted_message = cipher.encrypt(message.encode('utf-8'))
        encrypted_hex = base64.b64encode(encrypted_message).decode('utf-8')
        
        return jsonify({'encrypted_message': encrypted_hex})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rsa/decrypt', methods=['POST'])
def rsa_decrypt():
    try:
        data = request.get_json()
        ciphertext_hex = data['ciphertext']
        key_type = data['key_type']
        
        if rsa_cipher is None:
            return jsonify({'error': 'Keys not generated yet'}), 400
        
        # Load appropriate key
        if key_type == 'public':
            key = rsa_cipher.publickey()
        elif key_type == 'private':
            key = rsa_cipher
        else:
            return jsonify({'error': 'Invalid key type'}), 400
        
        # Decrypt message
        ciphertext = base64.b64decode(ciphertext_hex.encode('utf-8'))
        cipher = PKCS1_OAEP.new(key)
        decrypted_message = cipher.decrypt(ciphertext)
        
        return jsonify({'decrypted_message': decrypted_message.decode('utf-8')})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rsa/sign', methods=['POST'])
def rsa_sign_message():
    try:
        data = request.get_json()
        message = data['message']
        
        if rsa_cipher is None:
            return jsonify({'error': 'Keys not generated yet'}), 400
        
        # Create hash of message
        message_hash = SHA256.new(message.encode('utf-8'))
        
        # Sign the hash
        signature = pkcs1_15.new(rsa_cipher).sign(message_hash)
        signature_hex = base64.b64encode(signature).decode('utf-8')
        
        return jsonify({'signature': signature_hex})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rsa/verify', methods=['POST'])
def rsa_verify_signature():
    try:
        data = request.get_json()
        message = data['message']
        signature_hex = data['signature']
        
        if rsa_cipher is None:
            return jsonify({'error': 'Keys not generated yet'}), 400
        
        # Get public key
        public_key = rsa_cipher.publickey()
        
        # Decode signature
        signature = base64.b64decode(signature_hex.encode('utf-8'))
        
        # Create hash of message
        message_hash = SHA256.new(message.encode('utf-8'))
        
        # Verify signature
        try:
            pkcs1_15.new(public_key).verify(message_hash, signature)
            is_verified = True
        except (ValueError, TypeError):
            is_verified = False
        
        return jsonify({'valid': is_verified})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Additional utility endpoints
@app.route('/api/rsa/public_key', methods=['GET'])
def get_public_key():
    try:
        if rsa_cipher is None:
            return jsonify({'error': 'Keys not generated yet'}), 400
        
        public_key = rsa_cipher.publickey()
        public_key_pem = public_key.export_key().decode('utf-8')
        
        return jsonify({'public_key': public_key_pem})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rsa/key_info', methods=['GET'])
def get_key_info():
    try:
        if rsa_cipher is None:
            return jsonify({'error': 'Keys not generated yet'}), 400
        
        key_size = rsa_cipher.size_in_bits()
        has_private = rsa_cipher.has_private()
        
        return jsonify({
            'key_size': key_size,
            'has_private_key': has_private,
            'status': 'Keys loaded'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)