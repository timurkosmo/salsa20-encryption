"""
Менеджер операций шифрования и дешифрования
"""
import json
import base64
import sys
import os
from typing import Tuple, Optional

# Добавляем путь к модулям
sys.path.insert(0, os.path.dirname(__file__))

from salsa20_cipher import Salsa20Cipher
from integrity_checker import IntegrityChecker


class EncryptionManager:
    """Класс для управления процессом шифрования"""
    
    def __init__(self):
        self.cipher = Salsa20Cipher()
        self.checker = IntegrityChecker()
    
    def encrypt_text(self, plaintext: str) -> Tuple[bytes, bytes, bytes, str]:
        """
        Шифрование текста
        Возвращает: (ciphertext, key, nonce, hash)
        """
        # Генерация ключа и nonce
        key = Salsa20Cipher.generate_key()
        nonce = Salsa20Cipher.generate_nonce()
        
        # Преобразование текста в байты
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Вычисление хеш-суммы исходного текста
        original_hash = self.checker.compute_hash(plaintext_bytes)
        
        # Шифрование
        ciphertext = Salsa20Cipher.encrypt(plaintext_bytes, key, nonce)
        
        return ciphertext, key, nonce, original_hash
    
    def decrypt_text(self, ciphertext: bytes, key: bytes, nonce: bytes, 
                     expected_hash: str) -> Tuple[Optional[str], bool]:
        """
        Дешифрование текста с проверкой целостности
        Возвращает: (decrypted_text, integrity_ok)
        """
        try:
            # Дешифрование
            plaintext_bytes = Salsa20Cipher.decrypt(ciphertext, key, nonce)
            
            # Проверка целостности
            integrity_ok = self.checker.verify_hash(plaintext_bytes, expected_hash)
            
            # Преобразование в текст
            plaintext = plaintext_bytes.decode('utf-8')
            
            return plaintext, integrity_ok
        except Exception as e:
            return None, False
    
    def save_encrypted_data(self, filename: str, ciphertext: bytes, 
                           nonce: bytes, hash_value: str) -> None:
        """
        Сохранение зашифрованных данных в файл
        """
        data = {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'hash': hash_value
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    
    def load_encrypted_data(self, filename: str) -> Tuple[bytes, bytes, str]:
        """
        Загрузка зашифрованных данных из файла
        Возвращает: (ciphertext, nonce, hash)
        """
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        ciphertext = base64.b64decode(data['ciphertext'])
        nonce = base64.b64decode(data['nonce'])
        hash_value = data['hash']
        
        return ciphertext, nonce, hash_value
