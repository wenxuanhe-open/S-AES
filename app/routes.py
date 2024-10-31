# /app/routes.py
from flask import render_template, request
from app import app
from app.s_aes import s_aes_encrypt, s_aes_decrypt

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    plaintext = request.form.get('plaintext')
    key = request.form.get('key')
    operation = request.form.get('operation')

    if operation == 'encrypt':
        result = s_aes_encrypt(plaintext, key)
    elif operation == 'decrypt':
        result = s_aes_decrypt(plaintext, key)
    else:
        result = '选择的操作无效。'

    return render_template('result.html', result=result)