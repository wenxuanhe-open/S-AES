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
                # 对二进制输入进行处理
                plaintext = bits_to_text(plaintext)
                key = bits_to_text(key)
                
                # 根据模式进行加密
                if mode == 'single':
                    encrypted = s_aes_encrypt(plaintext, key)
                elif mode == 'double':
                    encrypted = double_encrypt(plaintext, key)
                elif mode == 'triple':
                    encrypted = triple_encrypt(plaintext, key)
                elif mode == 'cbc':
                    encrypted, iv = cbc_encrypt(plaintext, key)
                    result['iv'] = iv
                
                # 将结果转换回二进制
                result['ciphertext'] = text_to_bits(encrypted)
                
            else:  # ascii格式
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
                # 对二进制输入进行处理
                ciphertext = bits_to_text(ciphertext)
                key = bits_to_text(key)
                if iv:
                    iv = bits_to_text(iv)
                
                # 根据模式进行解密
                if mode == 'single':
                    decrypted = s_aes_decrypt(ciphertext, key)
                elif mode == 'double':
                    decrypted = double_decrypt(ciphertext, key)
                elif mode == 'triple':
                    decrypted = triple_decrypt(ciphertext, key)
                elif mode == 'cbc':
                    decrypted = cbc_decrypt(ciphertext, key, iv)
                
                # 将结果转换回二进制
                result['plaintext'] = text_to_bits(decrypted)
                
            else:  # ascii格式
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
        input_format = data.get('input_format', '')
        
        if input_format == 'binary':
            # 将输入的二进制转换为文本进行处理
            processed_pairs = [
                {
                    'plaintext': bits_to_text(p['plaintext']),
                    'ciphertext': bits_to_text(p['ciphertext'])
                }
                for p in pairs
            ]
            
            start_time = time.time()
            result = meet_in_the_middle_attack(
                [p['plaintext'] for p in processed_pairs],
                [p['ciphertext'] for p in processed_pairs]
            )
            end_time = time.time()
            
            # 将结果转换回二进制
            if result:
                result = [(text_to_bits(k1), text_to_bits(k2)) for k1, k2 in result]
        else:
            start_time = time.time()
            result = meet_in_the_middle_attack(
                [p['plaintext'] for p in pairs],
                [p['ciphertext'] for p in pairs]
            )
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