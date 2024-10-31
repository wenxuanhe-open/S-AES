# /tests/test_s_aes.py
import unittest
from app.s_aes import (
    s_aes_encrypt_text, s_aes_decrypt_text,
    double_encrypt, double_decrypt,
    triple_encrypt, triple_decrypt,
    cbc_encrypt, cbc_decrypt,
    meet_in_the_middle_attack
)

class TestSAES(unittest.TestCase):
    def test_ascii_encryption(self):
        plaintext = 'AB'
        key = '1234'
        ciphertext = s_aes_encrypt_text(plaintext, key)
        decrypted = s_aes_decrypt_text(ciphertext, key)
        self.assertEqual(decrypted, plaintext)

    def test_double_encryption(self):
        plaintext = '6F'
        key = 'ACBD'
        ciphertext = double_encrypt(plaintext, key)
        decrypted = double_decrypt(ciphertext, key)
        self.assertEqual(decrypted.upper(), plaintext.upper())

    def test_triple_encryption(self):
        plaintext = '6F'
        key = 'ACBD12'
        ciphertext = triple_encrypt(plaintext, key, mode=2)
        decrypted = triple_decrypt(ciphertext, key, mode=2)
        self.assertEqual(decrypted.upper(), plaintext.upper())

    def test_cbc_mode(self):
        plaintext = 'Hello, World!'
        key = '1234'
        iv = 'abcd'
        ciphertext = cbc_encrypt(plaintext, key, iv)
        decrypted = cbc_decrypt(ciphertext, key, iv)
        self.assertEqual(decrypted, plaintext)

    def test_meet_in_the_middle_attack(self):
        plaintext = '6F'
        key = 'ACBD'
        ciphertext = double_encrypt(plaintext, key)
        recovered_key = meet_in_the_middle_attack(plaintext, ciphertext)
        self.assertEqual(recovered_key.upper(), key.upper())

if __name__ == '__main__':
    unittest.main()