# /tests/test_s_aes.py
import unittest
from app.s_aes import s_aes_encrypt, s_aes_decrypt

class TestSAES(unittest.TestCase):
    def test_basic_encryption_decryption(self):
        plaintext = '6F'
        key = 'AC'
        ciphertext = s_aes_encrypt(plaintext, key)
        decrypted = s_aes_decrypt(ciphertext, key)
        self.assertEqual(decrypted, plaintext.upper())

    def test_double_encryption(self):
        # 实现双重加密的测试
        pass

    def test_triple_encryption(self):
        # 实现三重加密的测试
        pass

    def test_meet_in_the_middle_attack(self):
        # 实现中间相遇攻击的测试
        pass

    def test_cbc_mode(self):
        # 实现 CBC 模式的测试
        pass

if __name__ == '__main__':
    unittest.main()