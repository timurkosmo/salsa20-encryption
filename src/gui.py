"""
Графический интерфейс для программы шифрования
"""
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import base64
import sys
import os

# Добавляем путь к модулям
sys.path.insert(0, os.path.dirname(__file__))

from encryption_manager import EncryptionManager


class EncryptionGUI:
    """Класс графического интерфейса"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Salsa20 Encryption System")
        self.root.geometry("800x700")
        
        self.manager = EncryptionManager()
        self.current_key = None
        self.current_nonce = None
        self.current_hash = None
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Создание элементов интерфейса"""
        
        # Заголовок
        title_label = tk.Label(
            self.root, 
            text="Программа шифрования данных (Salsa20 + SHA-256)",
            font=('Arial', 14, 'bold')
        )
        title_label.pack(pady=10)
        
        # Фрейм для исходного текста
        input_frame = tk.LabelFrame(self.root, text="Исходный текст", padx=10, pady=10)
        input_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.input_text = scrolledtext.ScrolledText(
            input_frame, 
            height=8, 
            width=70,
            wrap=tk.WORD
        )
        self.input_text.pack()
        
        # Кнопки операций
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)
        
        encrypt_btn = tk.Button(
            button_frame,
            text="Зашифровать",
            command=self._encrypt,
            bg='#4CAF50',
            fg='white',
            width=15,
            height=2
        )
        encrypt_btn.grid(row=0, column=0, padx=5)
        
        decrypt_btn = tk.Button(
            button_frame,
            text="Расшифровать",
            command=self._decrypt,
            bg='#2196F3',
            fg='white',
            width=15,
            height=2
        )
        decrypt_btn.grid(row=0, column=1, padx=5)
        
        save_btn = tk.Button(
            button_frame,
            text="Сохранить в файл",
            command=self._save_to_file,
            width=15,
            height=2
        )
        save_btn.grid(row=0, column=2, padx=5)
        
        load_btn = tk.Button(
            button_frame,
            text="Загрузить из файла",
            command=self._load_from_file,
            width=15,
            height=2
        )
        load_btn.grid(row=0, column=3, padx=5)
        
        # Фрейм для зашифрованного текста
        output_frame = tk.LabelFrame(self.root, text="Результат", padx=10, pady=10)
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            height=8,
            width=70,
            wrap=tk.WORD
        )
        self.output_text.pack()
        
        # Фрейм для информации
        info_frame = tk.LabelFrame(self.root, text="Информация", padx=10, pady=10)
        info_frame.pack(fill='both', padx=10, pady=5)
        
        self.info_text = scrolledtext.ScrolledText(
            info_frame,
            height=6,
            width=70,
            wrap=tk.WORD
        )
        self.info_text.pack()
        
        # Статус
        self.status_label = tk.Label(
            self.root,
            text="Готов к работе",
            relief=tk.SUNKEN,
            anchor='w'
        )
        self.status_label.pack(fill='x', side='bottom')
    
    def _encrypt(self):
        """Обработка шифрования"""
        plaintext = self.input_text.get('1.0', tk.END).strip()
        
        if not plaintext:
            messagebox.showwarning("Предупреждение", "Введите текст для шифрования")
            return
        
        try:
            # Шифрование
            ciphertext, key, nonce, hash_value = self.manager.encrypt_text(plaintext)
            
            # Сохранение ключей
            self.current_key = key
            self.current_nonce = nonce
            self.current_hash = hash_value
            
            # Отображение результата
            cipher_b64 = base64.b64encode(ciphertext).decode('utf-8')
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', cipher_b64)
            
            # Отображение информации
            info = f"Шифрование выполнено успешно\n\n"
            info += f"Длина исходного текста: {len(plaintext)} символов\n"
            info += f"Длина зашифрованных данных: {len(ciphertext)} байт\n\n"
            info += f"SHA-256 хеш: {hash_value}\n\n"
            info += f"Ключ (base64): {base64.b64encode(key).decode('utf-8')[:50]}...\n"
            info += f"Nonce (base64): {base64.b64encode(nonce).decode('utf-8')}\n"
            
            self.info_text.delete('1.0', tk.END)
            self.info_text.insert('1.0', info)
            
            self.status_label.config(text="Шифрование выполнено")
            
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при шифровании: {str(e)}")
    
    def _decrypt(self):
        """Обработка дешифрования"""
        if not self.current_key or not self.current_nonce or not self.current_hash:
            messagebox.showwarning(
                "Предупреждение",
                "Сначала зашифруйте текст или загрузите ключ"
            )
            return
        
        cipher_b64 = self.output_text.get('1.0', tk.END).strip()
        
        if not cipher_b64:
            messagebox.showwarning("Предупреждение", "Нет зашифрованных данных")
            return
        
        try:
            # Декодирование из base64
            ciphertext = base64.b64decode(cipher_b64)
            
            # Дешифрование
            plaintext, integrity_ok = self.manager.decrypt_text(
                ciphertext,
                self.current_key,
                self.current_nonce,
                self.current_hash
            )
            
            if plaintext is None:
                messagebox.showerror("Ошибка", "Ошибка при дешифровании")
                return
            
            # Отображение результата
            self.input_text.delete('1.0', tk.END)
            self.input_text.insert('1.0', plaintext)
            
            # Информация о проверке целостности
            if integrity_ok:
                info = "Дешифрование выполнено успешно\n"
                info += "✓ Проверка целостности: ПРОЙДЕНА\n"
                info += "Данные не были изменены"
                self.status_label.config(text="Дешифрование выполнено, целостность подтверждена")
            else:
                info = "Дешифрование выполнено\n"
                info += "✗ Проверка целостности: НЕ ПРОЙДЕНА\n"
                info += "ВНИМАНИЕ: Данные могли быть изменены!"
                self.status_label.config(text="ВНИМАНИЕ: Целостность не подтверждена!")
                messagebox.showwarning(
                    "Предупреждение",
                    "Проверка целостности не пройдена!\nДанные могли быть изменены."
                )
            
            self.info_text.delete('1.0', tk.END)
            self.info_text.insert('1.0', info)
            
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при дешифровании: {str(e)}")
    
    def _save_to_file(self):
        """Сохранение зашифрованных данных в файл"""
        if not self.current_nonce or not self.current_hash:
            messagebox.showwarning("Предупреждение", "Нет данных для сохранения")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".encrypted",
            filetypes=[("Encrypted files", "*.encrypted"), ("All files", "*.*")]
        )
        
        if not filename:
            return
        
        try:
            cipher_b64 = self.output_text.get('1.0', tk.END).strip()
            ciphertext = base64.b64decode(cipher_b64)
            
            self.manager.save_encrypted_data(
                filename,
                ciphertext,
                self.current_nonce,
                self.current_hash
            )
            
            # Сохранение ключа отдельно
            key_filename = filename + ".key"
            with open(key_filename, 'w') as f:
                f.write(base64.b64encode(self.current_key).decode('utf-8'))
            
            messagebox.showinfo(
                "Успех",
                f"Данные сохранены в {filename}\nКлюч сохранен в {key_filename}"
            )
            self.status_label.config(text=f"Данные сохранены в {filename}")
            
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при сохранении: {str(e)}")
    
    def _load_from_file(self):
        """Загрузка зашифрованных данных из файла"""
        filename = filedialog.askopenfilename(
            filetypes=[("Encrypted files", "*.encrypted"), ("All files", "*.*")]
        )
        
        if not filename:
            return
        
        try:
            # Загрузка зашифрованных данных
            ciphertext, nonce, hash_value = self.manager.load_encrypted_data(filename)
            
            # Загрузка ключа
            key_filename = filename + ".key"
            with open(key_filename, 'r') as f:
                key_b64 = f.read().strip()
                key = base64.b64decode(key_b64)
            
            # Сохранение в текущие переменные
            self.current_key = key
            self.current_nonce = nonce
            self.current_hash = hash_value
            
            # Отображение зашифрованных данных
            cipher_b64 = base64.b64encode(ciphertext).decode('utf-8')
            self.output_text.delete('1.0', tk.END)
            self.output_text.insert('1.0', cipher_b64)
            
            # Информация
            info = f"Данные загружены из файла\n\n"
            info += f"SHA-256 хеш: {hash_value}\n"
            
            self.info_text.delete('1.0', tk.END)
            self.info_text.insert('1.0', info)
            
            messagebox.showinfo("Успех", "Данные успешно загружены")
            self.status_label.config(text=f"Данные загружены из {filename}")
            
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при загрузке: {str(e)}")
