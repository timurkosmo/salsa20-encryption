# Salsa20 Encryption System
Программный комплекс шифрования данных на основе алгоритма Salsa20 с контролем целостности SHA-256.

## Описание
Программа предназначена для шифрования и дешифрования текстовых документов с использованием:
Потокового шифра Salsa20 (256-bit ключ)
Контроля целостности SHA-256

## Требования
- Python 3.8 или выше
- PyCryptodome 3.19.0

## Установка
pip install -r requirements.txt

## Запуск
python src/main.py

## Структура проекта
salsa20-encryption/
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── salsa20_cipher.py
│   ├── integrity_checker.py
│   ├── encryption_manager.py
│   └── gui.py
├── tests/
│   ├── test_salsa20.py
│   └── run_tests.py
├── test_data/
│   ├── dataset_1.txt
│   ├── dataset_2.txt
│   └── dataset_3.txt
├── requirements.txt
├── .gitignore
└── README.md