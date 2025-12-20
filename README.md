# Salsa20 Encryption System

Программный комплекс шифрования данных на основе алгоритма Salsa20 с контролем целостности SHA-256.

## Требования

- Python 3.8 или выше
- PyCryptodome 3.19.0

## Установка

```bash
pip install -r requirements.txt
cat > README.md << 'EOF'
# Salsa20 Encryption System

Программный комплекс шифрования данных на основе алгоритма Salsa20 с контролем целостности SHA-256.

## Требования

- Python 3.8 или выше
- PyCryptodome 3.19.0

## Установка

```bash
pip install -r requirements.txt
python src/main.py
mkdir -p salsa20-encryption/src
mkdir -p salsa20-encryption/tests
mkdir -p salsa20-encryption/test_data
touch requirements.txt
touch .gitignore
touch README.md
touch src/__init__.py
touch src/main.py
touch src/salsa20_cipher.py
touch src/integrity_checker.py
touch src/encryption_manager.py
touch src/gui.py
touch tests/test_salsa20.py
touch tests/run_tests.py
cd /Users/vis/Documents/GitHub/salsa20-encryption 
touch requirements.txt .gitignore README.md src/__init__.py src/main.py src/salsa20_cipher.py src/integrity_checker.py src/encryption_manager.py src/gui.py tests/test_salsa20.py tests/run_tests.py test_data/dataset_1.txt test_data/dataset_2.txt test_data/dataset_3.txt && echo "Все файлы созданы" && ls -la && ls -la src/ && ls -la tests/ && ls -la test_data/
touch test_data/dataset_1.txt
touch test_data/dataset_2.txt
touch test_data/dataset_3.txt
cat > src/__init__.py << 'EOF'
"""
Программный комплекс шифрования данных на основе Salsa20
"""
__version__ = "1.0.0"
__author__ = "Космодемьянов Т.Б."
