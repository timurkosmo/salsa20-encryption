"""
Модуль реализации алгоритма шифрования Salsa20
"""
import struct
import secrets
from typing import Tuple


class Salsa20Cipher:
    """Класс для шифрования/дешифрования с использованием Salsa20"""
    
    CONSTANTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    
    def __init__(self):
        """Инициализация шифра"""
        pass
    
    @staticmethod
    def _rotate_left(value: int, shift: int) -> int:
        """Циклический сдвиг влево для 32-битного числа"""
        value &= 0xFFFFFFFF
        return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF
    
    @staticmethod
    def _quarter_round(y: list, a: int, b: int, c: int, d: int) -> None:
        """
        Базовая операция четверть-раунда Salsa20
        Модифицирует список y на месте
        """
        y[b] ^= Salsa20Cipher._rotate_left((y[a] + y[d]) & 0xFFFFFFFF, 7)
        y[c] ^= Salsa20Cipher._rotate_left((y[b] + y[a]) & 0xFFFFFFFF, 9)
        y[d] ^= Salsa20Cipher._rotate_left((y[c] + y[b]) & 0xFFFFFFFF, 13)
        y[a] ^= Salsa20Cipher._rotate_left((y[d] + y[c]) & 0xFFFFFFFF, 18)
    
    @staticmethod
    def _column_round(state: list) -> None:
        """Применение quarterround к столбцам матрицы"""
        Salsa20Cipher._quarter_round(state, 0, 4, 8, 12)
        Salsa20Cipher._quarter_round(state, 5, 9, 13, 1)
        Salsa20Cipher._quarter_round(state, 10, 14, 2, 6)
        Salsa20Cipher._quarter_round(state, 15, 3, 7, 11)
    
    @staticmethod
    def _row_round(state: list) -> None:
        """Применение quarterround к строкам матрицы"""
        Salsa20Cipher._quarter_round(state, 0, 1, 2, 3)
        Salsa20Cipher._quarter_round(state, 5, 6, 7, 4)
        Salsa20Cipher._quarter_round(state, 10, 11, 8, 9)
        Salsa20Cipher._quarter_round(state, 15, 12, 13, 14)
    
    @staticmethod
    def _double_round(state: list) -> None:
        """Один двойной раунд = column_round + row_round"""
        Salsa20Cipher._column_round(state)
        Salsa20Cipher._row_round(state)
    
    @staticmethod
    def _create_initial_state(key: bytes, nonce: bytes, counter: int) -> list:
        """
        Создание начального состояния матрицы 4x4
        key: 32 байта (256 бит)
        nonce: 8 байт (64 бита)
        counter: 8 байт (64 бита)
        """
        state = [0] * 16
        
        # Константы
        state[0] = Salsa20Cipher.CONSTANTS[0]
        state[5] = Salsa20Cipher.CONSTANTS[1]
        state[10] = Salsa20Cipher.CONSTANTS[2]
        state[15] = Salsa20Cipher.CONSTANTS[3]
        
        # Ключ (8 слов по 4 байта)
        for i in range(8):
            state[1 + i + (i // 4) * 2] = struct.unpack('<I', key[i*4:(i+1)*4])[0]
        
        # Nonce (2 слова)
        state[6] = struct.unpack('<I', nonce[0:4])[0]
        state[7] = struct.unpack('<I', nonce[4:8])[0]
        
        # Счетчик (2 слова)
        state[8] = counter & 0xFFFFFFFF
        state[9] = (counter >> 32) & 0xFFFFFFFF
        
        return state
    
    @staticmethod
    def _salsa20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
        """
        Генерация одного 64-байтового блока ключевого потока
        """
        # Создание начального состояния
        state = Salsa20Cipher._create_initial_state(key, nonce, counter)
        working_state = state.copy()
        
        # 10 двойных раундов (20 раундов)
        for _ in range(10):
            Salsa20Cipher._double_round(working_state)
        
        # Добавление начального состояния
        for i in range(16):
            working_state[i] = (working_state[i] + state[i]) & 0xFFFFFFFF
        
        # Преобразование в байты
        keystream = b''.join(struct.pack('<I', word) for word in working_state)
        return keystream
    
    @staticmethod
    def generate_key() -> bytes:
        """Генерация 256-битного ключа"""
        return secrets.token_bytes(32)
    
    @staticmethod
    def generate_nonce() -> bytes:
        """Генерация 64-битного nonce"""
        return secrets.token_bytes(8)
    
    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
        """
        Шифрование данных
        plaintext: открытый текст
        key: 32-байтовый ключ
        nonce: 8-байтовый nonce
        """
        ciphertext = bytearray()
        counter = 0
        
        # Обработка блоками по 64 байта
        for i in range(0, len(plaintext), 64):
            keystream = Salsa20Cipher._salsa20_block(key, nonce, counter)
            block = plaintext[i:i+64]
            
            # XOR с ключевым потоком
            for j in range(len(block)):
                ciphertext.append(block[j] ^ keystream[j])
            
            counter += 1
        
        return bytes(ciphertext)
    
    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
        """
        Дешифрование данных (идентично шифрованию из-за XOR)
        """
        return Salsa20Cipher.encrypt(ciphertext, key, nonce)