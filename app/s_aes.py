# /app/s_aes.py

SBOX = {
    '0000': '1001', '0001': '0100', '0010': '1010', '0011': '1011',
    '0100': '1101', '0101': '0001', '0110': '1000', '0111': '0101',
    '1000': '0110', '1001': '0010', '1010': '0000', '1011': '0011',
    '1100': '1100', '1101': '1110', '1110': '1111', '1111': '0111',
}

INV_SBOX = {v: k for k, v in SBOX.items()}

# GF(2^4)上的乘法
def gf_mul(a, b):
    irreducible = 0b10011  # x^4 + x + 1
    p = 0
    for i in range(4):
        if b & 1:
            p ^= a
        carry = a & 0b1000
        a <<= 1
        if carry:
            a ^= irreducible
        b >>= 1
    return p & 0b1111

def key_expansion(key):
    w = [''] * 6
    w[0] = key[:8]
    w[1] = key[8:]
    RCON = ['10000000', '00110000']
    
    def xor(a, b):
        return format(int(a, 2) ^ int(b, 2), '08b')
    
    def sub_nibble(byte):
        return SBOX[byte[:4]] + SBOX[byte[4:]]
    
    for i in range(2):
        temp = sub_nibble(w[2*i + 1])
        temp = xor(temp, RCON[i])
        w[2*i + 2] = xor(w[2*i], temp)
        w[2*i + 3] = xor(w[2*i + 2], w[2*i + 1])
    
    round_keys = [w[0] + w[1], w[2] + w[3], w[4] + w[5]]
    return round_keys

def add_round_key(state, key):
    return format(int(state, 2) ^ int(key, 2), '016b')

def substitute_nibbles(state):
    return ''.join([SBOX[state[i:i+4]] for i in range(0, 16, 4)])

def inverse_substitute_nibbles(state):
    return ''.join([INV_SBOX[state[i:i+4]] for i in range(0, 16, 4)])

def shift_rows(state):
    return state[:4] + state[12:16] + state[8:12] + state[4:8]

def mix_columns(state):
    s0 = state[:8]
    s1 = state[8:]
    s0_new = ''
    s1_new = ''
    a = int(s0[:4], 2)
    b = int(s0[4:], 2)
    c = int(s1[:4], 2)
    d = int(s1[4:], 2)
    s0_new = format(gf_mul(a, 1) ^ gf_mul(c, 4), '04b') + format(gf_mul(b, 1) ^ gf_mul(d, 4), '04b')
    s1_new = format(gf_mul(a, 4) ^ gf_mul(c, 1), '04b') + format(gf_mul(b, 4) ^ gf_mul(d, 1), '04b')
    return s0_new + s1_new

def inverse_shift_rows(state):
    return state[:4] + state[12:16] + state[8:12] + state[4:8]

def inverse_mix_columns(state):
    s0 = state[:8]
    s1 = state[8:]
    s0_new = ''
    s1_new = ''
    a = int(s0[:4], 2)
    b = int(s0[4:], 2)
    c = int(s1[:4], 2)
    d = int(s1[4:], 2)
    s0_new = format(gf_mul(a, 9) ^ gf_mul(c, 2), '04b') + format(gf_mul(b, 9) ^ gf_mul(d, 2), '04b')
    s1_new = format(gf_mul(a, 2) ^ gf_mul(c, 9), '04b') + format(gf_mul(b, 2) ^ gf_mul(d, 9), '04b')
    return s0_new + s1_new

def s_aes_encrypt_block(plaintext, key):
    state = plaintext
    round_keys = key_expansion(key)

    # 初始轮密钥加
    state = add_round_key(state, round_keys[0])

    # 轮1
    state = substitute_nibbles(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, round_keys[1])

    # 轮2
    state = substitute_nibbles(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[2])

    return state

def s_aes_decrypt_block(ciphertext, key):
    state = ciphertext
    round_keys = key_expansion(key)

    # 初始轮密钥加
    state = add_round_key(state, round_keys[2])

    # 轮1
    state = inverse_shift_rows(state)
    state = inverse_substitute_nibbles(state)
    state = add_round_key(state, round_keys[1])
    state = inverse_mix_columns(state)

    # 轮2
    state = inverse_shift_rows(state)
    state = inverse_substitute_nibbles(state)
    state = add_round_key(state, round_keys[0])

    return state

def text_to_bits(text):
    return ''.join(format(ord(c), '08b') for c in text)

def bits_to_text(bits):
    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    return ''.join(chr(int(c, 2)) for c in chars)

def s_aes_encrypt(plaintext, key):
    # 将plaintext和key转换为二进制
    plain_bits = text_to_bits(plaintext)
    key_bits = text_to_bits(key)
    # 分组
    blocks = [plain_bits[i:i+16] for i in range(0, len(plain_bits), 16)]
    cipher_blocks = []
    for block in blocks:
        if len(block) < 16:
            block = block.ljust(16, '0')
        cipher_block = s_aes_encrypt_block(block, key_bits[:16])
        cipher_blocks.append(cipher_block)
    cipher_bits = ''.join(cipher_blocks)
    ciphertext = bits_to_text(cipher_bits)
    return ciphertext

def s_aes_decrypt(ciphertext, key):
    # 将ciphertext和key转换为二进制
    cipher_bits = text_to_bits(ciphertext)
    key_bits = text_to_bits(key)
    # 分组
    blocks = [cipher_bits[i:i+16] for i in range(0, len(cipher_bits), 16)]
    plain_blocks = []
    for block in blocks:
        plain_block = s_aes_decrypt_block(block, key_bits[:16])
        plain_blocks.append(plain_block)
    plain_bits = ''.join(plain_blocks)
    plaintext = bits_to_text(plain_bits)
    return plaintext.strip('\x00')

# 双重加密和解密

def double_encrypt(plaintext, key):
    key_bits = text_to_bits(key)
    key1 = key_bits[:16]
    key2 = key_bits[16:32]
    cipher = s_aes_encrypt_block(text_to_bits(plaintext).ljust(16, '0'), key1)
    cipher = s_aes_encrypt_block(cipher, key2)
    return bits_to_text(cipher)

def double_decrypt(ciphertext, key):
    key_bits = text_to_bits(key)
    key1 = key_bits[:16]
    key2 = key_bits[16:32]
    plain = s_aes_decrypt_block(text_to_bits(ciphertext), key2)
    plain = s_aes_decrypt_block(plain, key1)
    return bits_to_text(plain).strip('\x00')

# 三重加密和解密
def triple_encrypt(plaintext, key):
    key_bits = text_to_bits(key)
    key1 = key_bits[:16]
    key2 = key_bits[16:32]
    if len(key_bits) == 48:
        key3 = key_bits[32:48]
    else:
        key3 = key1  # 若密钥长度为32位，使用K1
    cipher = s_aes_encrypt_block(text_to_bits(plaintext).ljust(16, '0'), key1)
    cipher = s_aes_encrypt_block(cipher, key2)
    cipher = s_aes_encrypt_block(cipher, key3)
    return bits_to_text(cipher)

def triple_decrypt(ciphertext, key):
    key_bits = text_to_bits(key)
    key1 = key_bits[:16]
    key2 = key_bits[16:32]
    if len(key_bits) == 48:
        key3 = key_bits[32:48]
    else:
        key3 = key1  # 若密钥长度为32位，使用K1
    plain = s_aes_decrypt_block(text_to_bits(ciphertext), key3)
    plain = s_aes_decrypt_block(plain, key2)
    plain = s_aes_decrypt_block(plain, key1)
    return bits_to_text(plain).strip('\x00')

# CBC模式加密和解密
import random

def cbc_encrypt(plaintext, key):
    iv = ''.join(chr(random.randint(0, 255)) for _ in range(2))
    iv_bits = text_to_bits(iv)
    key_bits = text_to_bits(key)
    blocks = [text_to_bits(plaintext[i:i+2]).ljust(16, '0') for i in range(0, len(plaintext), 2)]
    cipher_blocks = []
    prev_cipher = iv_bits
    for block in blocks:
        block = format(int(block, 2) ^ int(prev_cipher, 2), '016b')
        cipher_block = s_aes_encrypt_block(block, key_bits[:16])
        cipher_blocks.append(cipher_block)
        prev_cipher = cipher_block
    cipher_bits = ''.join(cipher_blocks)
    ciphertext = bits_to_text(cipher_bits)
    return ciphertext, iv

def cbc_decrypt(ciphertext, key, iv):
    iv_bits = text_to_bits(iv)
    key_bits = text_to_bits(key)
    cipher_blocks = [text_to_bits(ciphertext[i:i+2]) for i in range(0, len(ciphertext), 2)]
    plain_blocks = []
    prev_cipher = iv_bits
    for block in cipher_blocks:
        plain_block = s_aes_decrypt_block(block, key_bits[:16])
        plain_block = format(int(plain_block, 2) ^ int(prev_cipher, 2), '016b')
        plain_blocks.append(plain_block)
        prev_cipher = block
    plain_bits = ''.join(plain_blocks)
    plaintext = bits_to_text(plain_bits).strip('\x00')
    return plaintext

# 中间相遇攻击

# 中间相遇攻击
def meet_in_the_middle_attack(plaintext_attack, ciphertext_attack):
    plaintext_bits = text_to_bits(plaintext_attack).ljust(16, '0')
    ciphertext_bits = text_to_bits(ciphertext_attack).ljust(16, '0')

    forward_dict = {}
    for k1 in range(256):  # 枚举8位密钥K1
        key1 = format(k1, '08b').ljust(16, '0')
        mid = s_aes_encrypt_block(plaintext_bits, key1)
        forward_dict[mid] = key1

    for k2 in range(256):  # 枚举8位密钥K2
        key2 = format(k2, '08b').ljust(16, '0')
        mid = s_aes_decrypt_block(ciphertext_bits, key2)
        if mid in forward_dict:
            key1 = forward_dict[mid]
            return f'找到密钥组合：K1 = {int(key1[:8],2)}, K2 = {int(key2[:8],2)}'

    return '未找到匹配的密钥组合。'

def meet_in_the_middle_attack(plaintexts, ciphertexts):
    from itertools import product
    import time

    possible_keys = []

    # 将明文和密文转换为二进制
    plaintext_bits = [text_to_bits(p).ljust(16, '0') for p in plaintexts]
    ciphertext_bits = [text_to_bits(c).ljust(16, '0') for c in ciphertexts]

    start_time = time.time()

    # 生成所有可能的8位密钥
    keys = [format(k, '08b').ljust(16, '0') for k in range(256)]
    forward_dict = {}

    # 对于每个可能的K1，计算所有明文的中间值
    for key1 in keys:
        for pt in plaintext_bits:
            mid = s_aes_encrypt_block(pt, key1)
            forward_dict[(mid, key1)] = key1

    # 对于每个可能的K2，计算所有密文的中间值
    for key2 in keys:
        for ct in ciphertext_bits:
            mid = s_aes_decrypt_block(ct, key2)
            for (mid_fwd, key1) in forward_dict:
                if mid == mid_fwd:
                    possible_keys.append(f'可能的密钥组合：K1 = {key1}, K2 = {key2}')
                    if len(possible_keys) >= 5:  # 只输出前5个结果
                        break
            if len(possible_keys) >= 5:
                break
        if len(possible_keys) >= 5:
            break

    end_time = time.time()
    time_taken = end_time - start_time

    if possible_keys:
        result = '\n'.join(possible_keys)
    else:
        result = '未找到匹配的密钥组合。'

    return result


# 在 s_aes.py 中添加支持多对明密文的中间相遇攻击

def meet_in_the_middle_attack_multiple(pairs):
    keys_found = []
    # 假设密钥长度为16位，即8位的K1和8位的K2
    for k1 in range(256):
        key1 = format(k1, '08b').ljust(16, '0')
        mid_values = []
        for plaintext, _ in pairs:
            plaintext_bits = text_to_bits(plaintext).ljust(16, '0')
            mid = s_aes_encrypt_block(plaintext_bits, key1)
            mid_values.append(mid)
        forward_dict = {tuple(mid_values): key1}

        for k2 in range(256):
            key2 = format(k2, '08b').ljust(16, '0')
            mid_values = []
            for _, ciphertext in pairs:
                ciphertext_bits = text_to_bits(ciphertext).ljust(16, '0')
                mid = s_aes_decrypt_block(ciphertext_bits, key2)
                mid_values.append(mid)
            if tuple(mid_values) in forward_dict:
                key1_candidate = forward_dict[tuple(mid_values)]
                keys_found.append(f'K1 = {key1_candidate[:8]}, K2 = {key2[:8]}')

    return keys_found if keys_found else ['未找到匹配的密钥组合。']