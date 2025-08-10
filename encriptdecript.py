
import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
PBKDF2_ITER = 200_000

def derive_key(passphrase: str, salt: bytes) -> bytes:
    return PBKDF2(passphrase, salt, dkLen=KEY_SIZE, count=PBKDF2_ITER)

def encrypt_file(in_path: str, out_path: str, passphrase: str) -> None:
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(passphrase.encode('utf-8'), salt)
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    with open(in_path, 'rb') as f:
        plaintext = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    with open(out_path, 'wb') as f:
        f.write(salt + nonce + tag + ciphertext)

def decrypt_file(in_path: str, out_path: str, passphrase: str) -> None:
    with open(in_path, 'rb') as f:
        data = f.read()
    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    tag = data[SALT_SIZE + NONCE_SIZE:SALT_SIZE + NONCE_SIZE + TAG_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE + TAG_SIZE:]
    key = derive_key(passphrase.encode('utf-8'), salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    with open(out_path, 'wb') as f:
        f.write(plaintext)

class FileEncryptorGUI:
    def __init__(self, master):
        self.master = master
        master.title('🔒 File Encryptor / Decryptor - AES-GCM')
        master.geometry('700x500')
        master.configure(bg='#1e1e2f')

        style_fg = 'white'
        style_bg = '#2d2d44'
        font_title = ('Segoe UI', 14, 'bold')
        font_text = ('Segoe UI', 10)

        tk.Label(master, text='Secure File Encryption Tool', fg='#4deeea', bg='#1e1e2f', font=font_title).pack(pady=10)
        self.file_label = tk.Label(master, text='Selected file: (none)', fg=style_fg, bg='#1e1e2f', font=font_text)
        self.file_label.pack(padx=10, anchor='w')

        btn_frame = tk.Frame(master, bg='#1e1e2f')
        btn_frame.pack(fill='x', padx=10, pady=6)

        self.select_btn = tk.Button(btn_frame, text='📂 Select File', command=self.select_file, bg=style_bg, fg=style_fg, relief='flat')
        self.select_btn.pack(side='left', padx=5)

        self.file_clear_btn = tk.Button(btn_frame, text='❌ Clear', command=self.clear_selection, bg=style_bg, fg=style_fg, relief='flat')
        self.file_clear_btn.pack(side='left', padx=5)

        pass_frame = tk.Frame(master, bg='#1e1e2f')
        pass_frame.pack(fill='x', padx=10, pady=(6, 4))

        tk.Label(pass_frame, text='🔑 Passphrase:', fg=style_fg, bg='#1e1e2f').pack(side='left')
        self.pass_entry = tk.Entry(pass_frame, show='*', width=40, bg='#33334d', fg=style_fg, relief='flat')
        self.pass_entry.pack(side='left', padx=6)

        action_frame = tk.Frame(master, bg='#1e1e2f')
        action_frame.pack(fill='x', padx=10, pady=10)

        self.encrypt_btn = tk.Button(action_frame, text='Encrypt →', command=self.encrypt_action, bg='#28a745', fg='white', relief='flat')
        self.encrypt_btn.pack(side='left', padx=5)

        self.decrypt_btn = tk.Button(action_frame, text='Decrypt ←', command=self.decrypt_action, bg='#dc3545', fg='white', relief='flat')
        self.decrypt_btn.pack(side='left', padx=5)

        out_frame = tk.Frame(master, bg='#1e1e2f')
        out_frame.pack(fill='x', padx=10, pady=6)

        tk.Label(out_frame, text='💾 Output file (optional):', fg=style_fg, bg='#1e1e2f').pack(side='left')
        self.out_entry = tk.Entry(out_frame, width=45, bg='#33334d', fg=style_fg, relief='flat')
        self.out_entry.pack(side='left', padx=6)

        tk.Label(master, text='📜 Status Log:', fg=style_fg, bg='#1e1e2f').pack(anchor='w', padx=10)
        self.log = scrolledtext.ScrolledText(master, height=12, state='disabled', bg='#0f0f1a', fg='lime', relief='flat')
        self.log.pack(fill='both', expand=True, padx=10, pady=4)

        self.selected_file = None

    def log_msg(self, msg: str):
        self.log.configure(state='normal')
        self.log.insert('end', msg + '\n')
        self.log.see('end')
        self.log.configure(state='disabled')

    def select_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.selected_file = path
            self.file_label.configure(text=f'Selected file: {os.path.basename(path)}')
            self.log_msg(f'📂 Selected: {path}')

    def clear_selection(self):
        self.selected_file = None
        self.file_label.configure(text='Selected file: (none)')
        self.log_msg('❌ Cleared selection')

    def encrypt_action(self):
        if not self.selected_file:
            messagebox.showwarning('No file', 'Please select a file to encrypt')
            return
        passphrase = self.pass_entry.get()
        if not passphrase:
            messagebox.showwarning('No passphrase', 'Please enter a passphrase')
            return
        in_path = self.selected_file
        out_path = self.out_entry.get().strip() or in_path + '.enc'
        try:
            self.log_msg(f'🔒 Encrypting {in_path} → {out_path} ...')
            encrypt_file(in_path, out_path, passphrase)
            self.log_msg('✅ Encryption successful')
            messagebox.showinfo('Success', f'File encrypted:\n{out_path}')
        except Exception as e:
            self.log_msg(f'❌ Encryption failed: {e}')
            messagebox.showerror('Error', f'Encryption failed:\n{e}')

    def decrypt_action(self):
        if not self.selected_file:
            messagebox.showwarning('No file', 'Please select a file to decrypt')
            return
        passphrase = self.pass_entry.get()
        if not passphrase:
            messagebox.showwarning('No passphrase', 'Please enter a passphrase')
            return
        in_path = self.selected_file
        if self.out_entry.get().strip():
            out_path = self.out_entry.get().strip()
        else:
            out_path = in_path[:-4] if in_path.endswith('.enc') else in_path + '.dec'
        try:
            self.log_msg(f'🔓 Decrypting {in_path} → {out_path} ...')
            decrypt_file(in_path, out_path, passphrase)
            self.log_msg('✅ Decryption successful')
            messagebox.showinfo('Success', f'File decrypted:\n{out_path}')
        except Exception as e:
            self.log_msg(f'❌ Decryption failed: {e}')
            messagebox.showerror('Error', f'Decryption failed:\n{e}')

if __name__ == '__main__':
    root = tk.Tk()
    app = FileEncryptorGUI(root)
    root.mainloop()
