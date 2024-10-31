# /app/routes.py
from flask import render_template, request, jsonify
from app import app
from app.s_aes import *
import time

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        data = request.get_json()
        plaintext = data.get('plaintext', '')
        ciphertext = data.get('ciphertext', '')
        key = data.get('key', '')
        operation = data.get('operation', '')
        mode = data.get('mode', '')
        input_format = data.get('input_format', '')
        iv = data.get('iv', '')

        result = {}

        if operation == 'encrypt':
            if input_format == 'binary':
                plaintext = bits_to_text(plaintext)
                key = bits_to_text(key)
            
            if mode == 'single':
                result['ciphertext'] = s_aes_encrypt(plaintext, key)
            elif mode == 'double':
                result['ciphertext'] = double_encrypt(plaintext, key)
            elif mode == 'triple':
                result['ciphertext'] = triple_encrypt(plaintext, key)
            elif mode == 'cbc':
                ciphertext, iv = cbc_encrypt(plaintext, key)
                result['ciphertext'] = ciphertext
                result['iv'] = iv

        elif operation == 'decrypt':
            if input_format == 'binary':
                ciphertext = bits_to_text(ciphertext)
                key = bits_to_text(key)
            
            if mode == 'single':
                result['plaintext'] = s_aes_decrypt(ciphertext, key)
            elif mode == 'double':
                result['plaintext'] = double_decrypt(ciphertext, key)
            elif mode == 'triple':
                result['plaintext'] = triple_decrypt(ciphertext, key)
            elif mode == 'cbc':
                result['plaintext'] = cbc_decrypt(ciphertext, key, iv)

        return jsonify({'success': True, 'result': result})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/attack', methods=['GET'])
def attack():
    return render_template('attack.html')

@app.route('/attack_process', methods=['POST'])
def attack_process():
    try:
        data = request.get_json()
        pairs = data.get('pairs', [])
        
        start_time = time.time()
        result = meet_in_the_middle_attack([p['plaintext'] for p in pairs], 
                                         [p['ciphertext'] for p in pairs])
        end_time = time.time()
        time_taken = round(end_time - start_time, 3)

        return jsonify({
            'success': True,
            'result': result,
            'time_taken': time_taken
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })
    
    