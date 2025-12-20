"""
Скрипт для запуска всех тестов
"""
import unittest
import sys
import os

# Добавление пути к модулям
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

if __name__ == '__main__':
    # Поиск всех тестов
    loader = unittest.TestLoader()
    start_dir = os.path.dirname(__file__)
    suite = loader.discover(start_dir, pattern='test_*.py')
    
    # Запуск тестов
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Вывод статистики
    print("\n" + "="*70)
    print(f"Тестов запущено: {result.testsRun}")
    print(f"Успешно: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Ошибок: {len(result.failures)}")
    print(f"Провалено: {len(result.errors)}")
    print("="*70)
    
    sys.exit(0 if result.wasSuccessful() else 1)
