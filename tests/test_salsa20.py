"""
Модульные тесты для алгоритма Salsa20
"""
import unittest
import sys
import os

# Добавление пути к модулям
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from salsa20_cipher import Salsa20Cipher
from integrity_checker import IntegrityChecker
from encryption_manager import EncryptionManager


class TestSalsa20Cipher(unittest.TestCase):
    """Тесты для Salsa20"""
    
    def test_key_generation(self):
        """Тест генерации ключа"""
        key = Salsa20Cipher.generate_key()
        self.assertEqual(len(key), 32)
    
    def test_nonce_generation(self):
        """Тест генерации nonce"""
        nonce = Salsa20Cipher.generate_nonce()
        self.assertEqual(len(nonce), 8)
    
    def test_nonce_uniqueness(self):
        """Тест уникальности nonce"""
        nonce1 = Salsa20Cipher.generate_nonce()
        nonce2 = Salsa20Cipher.generate_nonce()
        self.assertNotEqual(nonce1, nonce2)
    
    def test_encrypt_decrypt(self):
        """Тест шифрования и дешифрования"""
        plaintext = b"Hello, World!"
        key = Salsa20Cipher.generate_key()
        nonce = Salsa20Cipher.generate_nonce()
        
        ciphertext = Salsa20Cipher.encrypt(plaintext, key, nonce)
        decrypted = Salsa20Cipher.decrypt(ciphertext, key, nonce)
        
        self.assertEqual(plaintext, decrypted)
    
    def test_different_keys(self):
        """Тест с разными ключами"""
        plaintext = b"Secret message"
        key1 = Salsa20Cipher.generate_key()
        key2 = Salsa20Cipher.generate_key()
        nonce = Salsa20Cipher.generate_nonce()
        
        cipher1 = Salsa20Cipher.encrypt(plaintext, key1, nonce)
        cipher2 = Salsa20Cipher.encrypt(plaintext, key2, nonce)
        
        self.assertNotEqual(cipher1, cipher2)
    
    def test_large_data(self):
        """Тест шифрования больших данных"""
        plaintext = b"A" * 1000
        key = Salsa20Cipher.generate_key()
        nonce = Salsa20Cipher.generate_nonce()
        
        ciphertext = Salsa20Cipher.encrypt(plaintext, key, nonce)
        decrypted = Salsa20Cipher.decrypt(ciphertext, key, nonce)
        
        self.assertEqual(plaintext, decrypted)


class TestIntegrityChecker(unittest.TestCase):
    """Тесты для проверки целостности"""
    
    def test_hash_computation(self):
        """Тест вычисления хеш-суммы"""
        data = b"Test data"
        hash1 = IntegrityChecker.compute_hash(data)
        hash2 = IntegrityChecker.compute_hash(data)
        
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)  # SHA-256 = 64 hex символа
    
    def test_hash_verification(self):
        """Тест проверки хеш-суммы"""
        data = b"Test data"
        hash_value = IntegrityChecker.compute_hash(data)
        
        self.assertTrue(IntegrityChecker.verify_hash(data, hash_value))
    
    def test_modified_data_detection(self):
        """Тест обнаружения модификации"""
        original_data = b"Original data"
        modified_data = b"Modified data"
        hash_value = IntegrityChecker.compute_hash(original_data)
        
        self.assertFalse(IntegrityChecker.verify_hash(modified_data, hash_value))
    
    def test_safe_compare(self):
        """Тест безопасного сравнения"""
        hash1 = "a" * 64
        hash2 = "a" * 64
        hash3 = "b" * 64
        
        self.assertTrue(IntegrityChecker.safe_compare(hash1, hash2))
        self.assertFalse(IntegrityChecker.safe_compare(hash1, hash3))


class TestEncryptionManager(unittest.TestCase):
    """Тесты для менеджера шифрования"""
    
    def setUp(self):
        """Подготовка к тестам"""
        self.manager = EncryptionManager()
    
    def test_encrypt_text(self):
        """Тест шифрования текста"""
        plaintext = "Тестовое сообщение"
        ciphertext, key, nonce, hash_value = self.manager.encrypt_text(plaintext)
        
        self.assertIsNotNone(ciphertext)
        self.assertEqual(len(key), 32)
        self.assertEqual(len(nonce), 8)
        self.assertEqual(len(hash_value), 64)
    
    def test_decrypt_text(self):
        """Тест дешифрования текста"""
        original_text = "Тестовое сообщение для шифрования"
        ciphertext, key, nonce, hash_value = self.manager.encrypt_text(original_text)
        
        decrypted_text, integrity_ok = self.manager.decrypt_text(
            ciphertext, key, nonce, hash_value
        )
        
        self.assertEqual(original_text, decrypted_text)
        self.assertTrue(integrity_ok)
    
    def test_integrity_check_fails(self):
        """Тест провала проверки целостности"""
        original_text = "Original message"
        ciphertext, key, nonce, hash_value = self.manager.encrypt_text(original_text)
        
        # Модифицируем зашифрованные данные
        modified_ciphertext = bytearray(ciphertext)
        modified_ciphertext[0] ^= 1
        
        decrypted_text, integrity_ok = self.manager.decrypt_text(
            bytes(modified_ciphertext), key, nonce, hash_value
        )
        
        self.assertIsNotNone(decrypted_text)
        self.assertFalse(integrity_ok)
    
    def test_cyrillic_text(self):
        """Тест с кириллическим текстом"""
        original_text = "Привет, мир! Тестируем шифрование."
        ciphertext, key, nonce, hash_value = self.manager.encrypt_text(original_text)
        
        decrypted_text, integrity_ok = self.manager.decrypt_text(
            ciphertext, key, nonce, hash_value
        )
        
        self.assertEqual(original_text, decrypted_text)
        self.assertTrue(integrity_ok)


if __name__ == '__main__':
    unittest.main()
