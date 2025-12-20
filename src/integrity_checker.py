"""
Модуль проверки целостности данных с использованием SHA-256
"""
import hashlib
from typing import Optional


class IntegrityChecker:
    """Класс для вычисления и проверки хеш-сумм SHA-256"""
    
    @staticmethod
    def compute_hash(data: bytes) -> str:
        """
        Вычисление SHA-256 хеш-суммы
        Возвращает шестнадцатеричное представление
        """
        sha256_hash = hashlib.sha256()
        sha256_hash.update(data)
        return sha256_hash.hexdigest()
    
    @staticmethod
    def verify_hash(data: bytes, expected_hash: str) -> bool:
        """
        Проверка целостности данных
        Возвращает True если хеш совпадает
        """
        actual_hash = IntegrityChecker.compute_hash(data)
        return actual_hash.lower() == expected_hash.lower()
    
    @staticmethod
    def safe_compare(hash1: str, hash2: str) -> bool:
        """
        Защищенное сравнение хеш-сумм (защита от атак по времени)
        """
        if len(hash1) != len(hash2):
            return False
        
        result = 0
        for c1, c2 in zip(hash1, hash2):
            result |= ord(c1) ^ ord(c2)
        
        return result == 0
