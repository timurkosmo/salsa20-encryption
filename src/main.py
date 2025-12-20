"""
Главный модуль приложения шифрования Salsa20
"""
import tkinter as tk
import sys
import os

# Добавляем путь к модулям
sys.path.insert(0, os.path.dirname(__file__))

from gui import EncryptionGUI


def main():
    """Точка входа в приложение"""
    root = tk.Tk()
    app = EncryptionGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
