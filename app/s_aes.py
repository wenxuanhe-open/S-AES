# /app/s_aes.py
SBOX = {
    '0000': '1001', '0001': '0100', '0010': '1010', '0011': '1011',
    '0100': '1101', '0101': '0001', '0110': '1000', '0111': '0101',
    '1000': '0110', '1001': '0010', '1010': '0000', '1011': '0011',
    '1100': '1100', '1101': '1110', '1110': '1111', '1111': '0111',
}

INV_SBOX = {v: k for k, v in SBOX.items()}

# 在 GF(2^4) 中乘法
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
    RCON1 = '10000000'
    RCON2 = '00110000'

    def xor(a, b):
        return format(int(a, 2) ^ int(b, 2), '08b')

    def sub_nibble(byte):
        return SBOX[byte[:4]] + SBOX[byte[4:]]

    w[2] = xor(w[0], xor(RCON1, sub_nibble(w[1])))
    w[3] = xor(w[2], w[1])
    w[4] = xor(w[2], xor(RCON2, sub_nibble(w[3])))
    w[5] = xor(w[4], w[3])

    round_keys = [w[0] + w[1], w[2] + w[3], w[4] + w[5]]
    return round_keys

def add_round_key(state, key):
    return format(int(state, 2) ^ int(key, 2), '16b').zfill(16)

def substitute_nibbles(state):
    return ''.join([SBOX[state[i:i+4]] for i in range(0, 16, 4)])

def inverse_substitute_nibbles(state):
    return ''.join([INV_SBOX[state[i:i+4]] for i in range(0, 16, 4)])

def shift_rows(state):
    return state[:4] + state[12:16] + state[8:12] + state[4:8]

def inverse_shift_rows(state):
    return state[:4] + state[12:16] + state[8:12] + state[4:8]

def mix_columns(state):
    s0 = state[:8]
    s1 = state[8:]
    s0_left = s0[:4]
    s0_right = s0[4:]
    s1_left = s1[:4]
    s1_right = s1[4:]

    s0_new = format(gf_mul(int(s0_left, 2), 1) ^ gf_mul(int(s1_left, 2), 4), '04b') + \
             format(gf_mul(int(s0_right, 2), 1) ^ gf_mul(int(s1_right, 2), 4), '04b')
    s1_new = format(gf_mul(int(s0_left, 2), 4) ^ gf_mul(int(s1_left, 2), 1), '04b') + \
             format(gf_mul(int(s0_right, 2), 4) ^ gf_mul(int(s1_right, 2), 1), '04b')
    return s0_new + s1_new

def inverse_mix_columns(state):
    # 实现与 mix_columns 类似的逆列混合，但使用逆系数
    pass  # 为简洁起见，省略了实现

def s_aes_encrypt(plaintext, key):
    # 将明文和密钥转换为二进制
    state = format(int(plaintext, 16), '016b')
    key_bin = format(int(key, 16), '016b')

    round_keys = key_expansion(key_bin)

    # 初始 AddRoundKey
    state = add_round_key(state, round_keys[0])

    # 第1轮
    state = substitute_nibbles(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, round_keys[1])

    # 第2轮
    state = substitute_nibbles(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[2])

    ciphertext = hex(int(state, 2))[2:].zfill(4).upper()
    return ciphertext

def s_aes_decrypt(ciphertext, key):
    # 将密文和密钥转换为二进制
    state = format(int(ciphertext, 16), '016b')
    key_bin = format(int(key, 16), '016b')

    round_keys = key_expansion(key_bin)

    # 初始 AddRoundKey
    state = add_round_key(state, round_keys[2])

    # 第1轮
    state = inverse_shift_rows(state)
    state = inverse_substitute_nibbles(state)
    state = add_round_key(state, round_keys[1])
    state = inverse_mix_columns(state)
    
    # 第2轮
    state = inverse_shift_rows(state)
    state = inverse_substitute_nibbles(state)
    state = add_round_key(state, round_keys[0])

    plaintext = hex(int(state, 2))[2:].zfill(4).upper()
    return plaintext