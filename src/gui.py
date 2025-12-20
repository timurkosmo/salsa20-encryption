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
        self.root.geometry("800x750")
        
        self.manager = EncryptionManager()
        self.current_key = None
        self.current_nonce = None
        self.current_hash = None
        
        self._create_widgets()
    
    def _on_button_enter(self, event):
        """Изменение цвета при наведении"""
        event.widget['background'] = '#E0E0E0'
    
    def _on_button_leave(self, event):
        """Возврат цвета при уходе курсора"""
        event.widget['background'] = 'SystemButtonFace'
    
    def _on_action_button_enter(self, event, color):
        """Изменение цвета для цветных кнопок при наведении"""
        if color == 'green':
            event.widget['background'] = '#45A049'
        elif color == 'blue':
            event.widget['background'] = '#1976D2'
    
    def _on_action_button_leave(self, event, color):
        """Возврат цвета для цветных кнопок"""
        if color == 'green':
            event.widget['background'] = '#4CAF50'
        elif color == 'blue':
            event.widget['background'] = '#2196F3'
    
    def _paste_text(self, text_widget):
        """Вставка текста из буфера обмена"""
        try:
            text = self.root.clipboard_get()
            text_widget.insert(tk.INSERT, text)
            return "break"
        except tk.TclError:
            pass
    
    def _copy_text(self, text_widget):
        """Копирование текста в буфер обмена"""
        try:
            text = text_widget.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            return "break"
        except tk.TclError:
            pass
    
    def _cut_text(self, text_widget):
        """Вырезание текста"""
        try:
            text = text_widget.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            text_widget.delete(tk.SEL_FIRST, tk.SEL_LAST)
            return "break"
        except tk.TclError:
            pass
    
    def _select_all(self, text_widget):
        """Выделение всего текста"""
        text_widget.tag_add(tk.SEL, "1.0", tk.END)
        text_widget.mark_set(tk.INSERT, "1.0")
        text_widget.see(tk.INSERT)
        return "break"
    
    def _create_context_menu(self, text_widget):
        """Создание контекстного меню"""
        menu = tk.Menu(text_widget, tearoff=0)
        menu.add_command(label="Вставить (Ctrl+V)", command=lambda: self._paste_text(text_widget))
        menu.add_command(label="Копировать (Ctrl+C)", command=lambda: self._copy_text(text_widget))
        menu.add_command(label="Вырезать (Ctrl+X)", command=lambda: self._cut_text(text_widget))
        menu.add_separator()
        menu.add_command(label="Выделить все (Ctrl+A)", command=lambda: self._select_all(text_widget))
        
        def show_menu(event):
            menu.post(event.x_root, event.y_root)
        
        text_widget.bind("<Button-3>", show_menu)  # Правая кнопка мыши
    
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
        
        # Подсказка
        hint_label = tk.Label(
            input_frame,
            text="Введите или вставьте текст (Ctrl+V)",
            font=('Arial', 9, 'italic'),
            fg='gray'
        )
        hint_label.pack(anchor='w')
        
        self.input_text = scrolledtext.ScrolledText(
            input_frame, 
            height=8, 
            width=70,
            wrap=tk.WORD,
            font=('Courier', 10)
        )
        self.input_text.pack()
        
        # Привязка горячих клавиш для поля ввода
        self.input_text.bind('<Control-v>', lambda e: self._paste_text(self.input_text))
        self.input_text.bind('<Control-V>', lambda e: self._paste_text(self.input_text))
        self.input_text.bind('<Control-c>', lambda e: self._copy_text(self.input_text))
        self.input_text.bind('<Control-C>', lambda e: self._copy_text(self.input_text))
        self.input_text.bind('<Control-x>', lambda e: self._cut_text(self.input_text))
        self.input_text.bind('<Control-X>', lambda e: self._cut_text(self.input_text))
        self.input_text.bind('<Control-a>', lambda e: self._select_all(self.input_text))
        self.input_text.bind('<Control-A>', lambda e: self._select_all(self.input_text))
        
        # Для Mac
        self.input_text.bind('<Command-v>', lambda e: self._paste_text(self.input_text))
        self.input_text.bind('<Command-c>', lambda e: self._copy_text(self.input_text))
        self.input_text.bind('<Command-x>', lambda e: self._cut_text(self.input_text))
        self.input_text.bind('<Command-a>', lambda e: self._select_all(self.input_text))
        
        # Контекстное меню
        self._create_context_menu(self.input_text)
        
        # Кнопки операций
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)
        
        # Кнопка "Зашифровать"
        encrypt_btn = tk.Button(
            button_frame,
            text="Зашифровать",
            command=self._encrypt,
            bg='#4CAF50',
            fg='black',
            width=15,
            height=2,
            font=('Arial', 10, 'bold'),
            cursor='hand2',
            activebackground='#45A049',
            activeforeground='black',
            relief=tk.RAISED,
            bd=3
        )
        encrypt_btn.grid(row=0, column=0, padx=5)
        encrypt_btn.bind('<Enter>', lambda e: self._on_action_button_enter(e, 'green'))
        encrypt_btn.bind('<Leave>', lambda e: self._on_action_button_leave(e, 'green'))
        
        # Кнопка "Расшифровать"
        decrypt_btn = tk.Button(
            button_frame,
            text="Расшифровать",
            command=self._decrypt,
            bg='#2196F3',
            fg='black',
            width=15,
            height=2,
            font=('Arial', 10, 'bold'),
            cursor='hand2',
            activebackground='#1976D2',
            activeforeground='black',
            relief=tk.RAISED,
            bd=3
        )
        decrypt_btn.grid(row=0, column=1, padx=5)
        decrypt_btn.bind('<Enter>', lambda e: self._on_action_button_enter(e, 'blue'))
        decrypt_btn.bind('<Leave>', lambda e: self._on_action_button_leave(e, 'blue'))
        
        # Кнопка "Сохранить в файл"
        save_btn = tk.Button(
            button_frame,
            text="Сохранить в файл",
            command=self._save_to_file,
            width=15,
            height=2,
            font=('Arial', 10),
            cursor='hand2',
            relief=tk.RAISED,
            bd=3
        )
        save_btn.grid(row=0, column=2, padx=5)
        save_btn.bind('<Enter>', self._on_button_enter)
        save_btn.bind('<Leave>', self._on_button_leave)
        
        # Кнопка "Загрузить из файла"
        load_btn = tk.Button(
            button_frame,
            text="Загрузить из файла",
            command=self._load_from_file,
            width=15,
            height=2,
            font=('Arial', 10),
            cursor='hand2',
            relief=tk.RAISED,
            bd=3
        )
        load_btn.grid(row=0, column=3, padx=5)
        load_btn.bind('<Enter>', self._on_button_enter)
        load_btn.bind('<Leave>', self._on_button_leave)
        
        # Фрейм для зашифрованного текста
        output_frame = tk.LabelFrame(self.root, text="Результат", padx=10, pady=10)
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            height=8,
            width=70,
            wrap=tk.WORD,
            font=('Courier', 10)
        )
        self.output_text.pack()
        
        # Привязка горячих клавиш для поля вывода
        self.output_text.bind('<Control-v>', lambda e: self._paste_text(self.output_text))
        self.output_text.bind('<Control-V>', lambda e: self._paste_text(self.output_text))
        self.output_text.bind('<Control-c>', lambda e: self._copy_text(self.output_text))
        self.output_text.bind('<Control-C>', lambda e: self._copy_text(self.output_text))
        self.output_text.bind('<Control-a>', lambda e: self._select_all(self.output_text))
        self.output_text.bind('<Control-A>', lambda e: self._select_all(self.output_text))
        
        # Для Mac
        self.output_text.bind('<Command-v>', lambda e: self._paste_text(self.output_text))
        self.output_text.bind('<Command-c>', lambda e: self._copy_text(self.output_text))
        self.output_text.bind('<Command-a>', lambda e: self._select_all(self.output_text))
        
        # Контекстное меню
        self._create_context_menu(self.output_text)
        
        # Фрейм для информации
        info_frame = tk.LabelFrame(self.root, text="Информация", padx=10, pady=10)
        info_frame.pack(fill='both', padx=10, pady=5)
        
        self.info_text = scrolledtext.ScrolledText(
            info_frame,
            height=6,
            width=70,
            wrap=tk.WORD,
            font=('Courier', 9)
        )
        self.info_text.pack()
        
        # Привязка для информационного поля
        self.info_text.bind('<Control-c>', lambda e: self._copy_text(self.info_text))
        self.info_text.bind('<Control-C>', lambda e: self._copy_text(self.info_text))
        self.info_text.bind('<Control-a>', lambda e: self._select_all(self.info_text))
        self.info_text.bind('<Control-A>', lambda e: self._select_all(self.info_text))
        
        # Для Mac
        self.info_text.bind('<Command-c>', lambda e: self._copy_text(self.info_text))
        self.info_text.bind('<Command-a>', lambda e: self._select_all(self.info_text))
        
        # Контекстное меню
        self._create_context_menu(self.info_text)
        
        # Статус
        self.status_label = tk.Label(
            self.root,
            text="Готов к работе | Используйте Ctrl+V для вставки текста или правую кнопку мыши",
            relief=tk.SUNKEN,
            anchor='w',
            font=('Arial', 9)
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
            
            self.status_label.config(text="Шифрование выполнено успешно")
            
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
