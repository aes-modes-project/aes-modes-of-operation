"""Andrew's desktop GUI for the team's AES modes implementation.

Launch from the repository root with: python andrew_gui.py
This is an optional Tkinter desktop interface; it does not replace the Flask learning app.
"""
import tkinter as tk
from tkinter import ttk, messagebox

from aesmodes import encrypt, decrypt

DEFAULT_KEY = '000102030405060708090a0b0c0d0e0f'
DEFAULT_COUNTER = '00000000000000000000000000000001'


class AESModesGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('AES-128 Modes Explorer | Andrew — CTR & GUI')
        self.geometry('900x730')
        self.minsize(720, 620)
        self.configure(bg='#101828')
        self.mode = tk.StringVar(value='CTR')
        self.key = tk.StringVar(value=DEFAULT_KEY)
        self.counter = tk.StringVar(value=DEFAULT_COUNTER)
        self.operation = tk.StringVar(value='Encrypt')
        self._build()

    def _build(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('TFrame', background='#101828')
        style.configure('TLabel', background='#101828', foreground='#e7eef8', font=('Segoe UI', 11))
        style.configure('Header.TLabel', font=('Segoe UI', 20, 'bold'), foreground='#ffffff')
        style.configure('Hint.TLabel', foreground='#a5b4ce', font=('Segoe UI', 9))
        style.configure('TButton', padding=9, font=('Segoe UI', 10, 'bold'))
        style.configure('TEntry', padding=7)
        style.configure('TCombobox', padding=5)
        main = ttk.Frame(self, padding=24)
        main.pack(fill='both', expand=True)
        ttk.Label(main, text='AES-128 Modes Explorer', style='Header.TLabel').pack(anchor='w')
        ttk.Label(main, text='Educational demo · AES is implemented by the team’s Python package', style='Hint.TLabel').pack(anchor='w', pady=(4, 18))

        options = ttk.Frame(main)
        options.pack(fill='x')
        ttk.Label(options, text='Mode').grid(row=0, column=0, sticky='w', pady=5)
        mode_select = ttk.Combobox(options, textvariable=self.mode, values=('ECB', 'CBC', 'CFB', 'OFB', 'CTR'), state='readonly', width=14)
        mode_select.grid(row=0, column=1, sticky='w', padx=(12, 30), pady=5)
        mode_select.bind('<<ComboboxSelected>>', lambda _: self._update_counter())
        ttk.Label(options, text='Operation').grid(row=0, column=2, sticky='w', pady=5)
        ttk.Combobox(options, textvariable=self.operation, values=('Encrypt', 'Decrypt'), state='readonly', width=14).grid(row=0, column=3, sticky='w', padx=12, pady=5)
        ttk.Label(options, text='AES-128 key (32 hexadecimal characters)').grid(row=1, column=0, columnspan=4, sticky='w', pady=(14, 4))
        ttk.Entry(options, textvariable=self.key, width=56).grid(row=2, column=0, columnspan=4, sticky='ew', pady=(0, 10))
        ttk.Label(options, text='Initial CTR counter (up to 32 hexadecimal characters)').grid(row=3, column=0, columnspan=4, sticky='w', pady=(8, 4))
        self.counter_entry = ttk.Entry(options, textvariable=self.counter, width=56)
        self.counter_entry.grid(row=4, column=0, columnspan=4, sticky='ew', pady=(0, 5))
        options.columnconfigure(3, weight=1)
        self._update_counter()

        ttk.Label(main, text='Input — plaintext (encrypt) or hexadecimal ciphertext (decrypt)').pack(anchor='w', pady=(17, 6))
        self.input_box = tk.Text(main, height=6, wrap='word', bg='#19283d', fg='#ffffff', insertbackground='white', relief='flat', padx=12, pady=12, font=('Consolas', 11))
        self.input_box.pack(fill='both', expand=True)
        self.input_box.insert('1.0', 'Hello, AES modes!')
        buttons = ttk.Frame(main)
        buttons.pack(fill='x', pady=12)
        ttk.Button(buttons, text='Run', command=self.run_operation).pack(side='left', padx=(0, 8))
        ttk.Button(buttons, text='Use output as input', command=self.copy_output_to_input).pack(side='left', padx=8)
        ttk.Button(buttons, text='Clear', command=self.clear).pack(side='left', padx=8)
        ttk.Label(main, text='Output').pack(anchor='w', pady=(5, 6))
        self.output_box = tk.Text(main, height=5, wrap='word', bg='#19283d', fg='#8fffd5', relief='flat', padx=12, pady=12, font=('Consolas', 11))
        self.output_box.pack(fill='both', expand=True)
        ttk.Label(main, text='Note: CTR uses AES encryption for both directions. The same key and starting counter are needed to decrypt.', style='Hint.TLabel', wraplength=790).pack(anchor='w', pady=(12, 0))

    def _update_counter(self):
        self.counter_entry.configure(state='normal' if self.mode.get() == 'CTR' else 'disabled')

    def run_operation(self):
        try:
            key_hex = self.key.get().strip()
            if len(key_hex) != 32:
                raise ValueError('AES-128 requires a 32-character hexadecimal key (16 bytes).')
            key = bytes.fromhex(key_hex)
            mode = self.mode.get()
            operation = self.operation.get()
            entered = self.input_box.get('1.0', 'end-1c')
            if operation == 'Encrypt':
                payload = entered.encode('utf-8')
            else:
                payload = bytes.fromhex(''.join(entered.split()))
            kwargs = {}
            if mode == 'CTR':
                counter = self.counter.get().strip().removeprefix('0x')
                if not counter or len(counter) > 32:
                    raise ValueError('CTR initial counter must contain 1 to 32 hexadecimal characters.')
                int(counter, 16)
                kwargs['counter'] = counter
            if operation == 'Encrypt':
                result = encrypt(mode, key, payload, **kwargs)
                answer = result.output.hex()
            else:
                result = decrypt(mode, key, payload, **kwargs)
                try:
                    answer = result.output.decode('utf-8')
                except UnicodeDecodeError:
                    answer = 'Hex (not UTF-8 text): ' + result.output.hex()
            self.output_box.delete('1.0', tk.END)
            self.output_box.insert('1.0', answer)
        except (ValueError, TypeError, UnicodeError) as exc:
            messagebox.showerror('Invalid input', str(exc))
        except Exception as exc:
            messagebox.showerror('Operation failed', f'{type(exc).__name__}: {exc}')

    def copy_output_to_input(self):
        data = self.output_box.get('1.0', 'end-1c')
        if data:
            self.input_box.delete('1.0', tk.END)
            self.input_box.insert('1.0', data)
            self.operation.set('Decrypt' if self.operation.get() == 'Encrypt' else 'Encrypt')

    def clear(self):
        self.input_box.delete('1.0', tk.END)
        self.output_box.delete('1.0', tk.END)


if __name__ == '__main__':
    AESModesGUI().mainloop()
