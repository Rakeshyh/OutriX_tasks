import re
import hashlib
import math
import random
import string
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox

def check_strength(password):
    reasons = []
    suggestions = []
    if len(password) < 8:
        reasons.append("✘ Less than 8 characters")
        suggestions.append("✓ Use at least 8 characters")
    else:
        reasons.append("✔ Good length")
    if not re.search(r"[A-Z]", password):
        reasons.append("✘ No uppercase letters")
        suggestions.append("✓ Add uppercase letters (A-Z)")
    else:
        reasons.append("✔ Has uppercase letter(s)")
    if not re.search(r"[a-z]", password):
        reasons.append("✘ No lowercase letters")
        suggestions.append("✓ Add lowercase letters (a-z)")
    else:
        reasons.append("✔ Has lowercase letter(s)")
    if not re.search(r"[0-9]", password):
        reasons.append("✘ No numbers")
        suggestions.append("✓ Include numbers (0-9)")
    else:
        reasons.append("✔ Has number(s)")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        reasons.append("✘ No special characters")
        suggestions.append("✓ Include symbols like !@#$%^")
    else:
        reasons.append("✔ Has special character(s)")
    score = sum([
        len(password) >= 8,
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"[0-9]", password)),
        bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
    ])
    if score == 5:
        strength = "Password is STRONG"
    elif score >= 3:
        strength = "Password is MODERATE"
    else:
        strength = "Password is WEAK"
    return strength, reasons, suggestions

def calculate_entropy(password):
    charset_size = 0
    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"[0-9]", password):
        charset_size += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        charset_size += 32
    if charset_size == 0:
        return 0
    entropy = len(password) * math.log2(charset_size)
    return round(entropy, 2)

def generate_strong_password(length=12):
    all_chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choices(all_chars, k=length))

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def save_to_file(password, strength, entropy):
    line = f"{datetime.now()} | Password: {'*' * len(password)} | Strength: {strength} | Entropy: {entropy} bits\n"
    with open("password_report.txt", "a", encoding="utf-8") as file:
        file.write(line)

class PasswordCheckerApp:
    def __init__(self, root):
        self.root = root
        root.title("Advanced Password Strength Checker")
        root.geometry("650x700")
        root.configure(bg="#1e1e2f")
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TLabel", foreground="white", background="#1e1e2f", font=("Segoe UI", 11))
        style.configure("TButton", font=("Segoe UI", 11, "bold"), background="#00bfff", foreground="white")
        style.map("TButton",
                  foreground=[('active', 'white')],
                  background=[('active', '#0080ff')])
        style.configure("Header.TLabel", font=("Segoe UI", 20, "bold"), foreground="#00ffff", background="#1e1e2f")
        self.header_label = ttk.Label(root, text="🔐 Advanced Password Strength Checker 🔐", style="Header.TLabel")
        self.header_label.grid(row=0, column=0, columnspan=4, pady=(20, 15), sticky="nsew")
        ttk.Label(root, text="Check Password Strength", background="#1e1e2f",
                  foreground="white", font=("Segoe UI", 14, "bold")).grid(row=1, column=0, sticky="w", padx=20)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(root, textvariable=self.password_var, font=("Segoe UI", 12), width=30, show="*")
        self.password_entry.grid(row=2, column=0, padx=20, pady=5, sticky="w")
        self.show_password_var = tk.BooleanVar(value=False)
        self.show_password_cb = ttk.Checkbutton(root, text="Show Password", variable=self.show_password_var,
                                                command=self.toggle_show_password)
        self.show_password_cb.grid(row=2, column=1, sticky="w", pady=5)
        self.check_btn = ttk.Button(root, text="Check Strength", command=self.check_password_strength)
        self.check_btn.grid(row=2, column=2, padx=15, sticky="w")
        self.result_text = tk.Text(root, height=15, width=75, bg="#2e2e3e", fg="white", font=("Consolas", 11))
        self.result_text.grid(row=3, column=0, columnspan=4, padx=20, pady=15)
        self.result_text.config(state="disabled")
        ttk.Label(root, text="Generate Strong Password", background="#1e1e2f",
                  foreground="white", font=("Segoe UI", 14, "bold")).grid(row=4, column=0, sticky="w", padx=20, pady=(20, 5))
        ttk.Label(root, text="Enter password length (min 8):", background="#1e1e2f", foreground="white").grid(row=5, column=0, sticky="w", padx=20)
        self.length_var = tk.StringVar(value="12")
        self.length_entry = ttk.Entry(root, textvariable=self.length_var, width=6, font=("Segoe UI", 12))
        self.length_entry.grid(row=5, column=1, sticky="w")
        self.show_generated_var = tk.BooleanVar(value=False)
        self.show_generated_cb = ttk.Checkbutton(root, text="Show Password", variable=self.show_generated_var,
                                                 command=self.toggle_show_generated_password)
        self.show_generated_cb.grid(row=5, column=2, sticky="w")
        self.generate_btn = ttk.Button(root, text="Generate Password", command=self.generate_password)
        self.generate_btn.grid(row=5, column=3, sticky="w", padx=15)
        self.generated_password_var = tk.StringVar()
        self.generated_password_entry = ttk.Entry(root, textvariable=self.generated_password_var,
                                                  font=("Segoe UI", 12), width=50, state="readonly", justify="center")
        self.generated_password_entry.grid(row=6, column=0, columnspan=4, padx=20, pady=10)
        self.exit_btn = ttk.Button(root, text="Exit", command=self.exit_program)
        self.exit_btn.grid(row=7, column=0, columnspan=4, pady=30)
        root.grid_columnconfigure(0, weight=1)
        root.grid_columnconfigure(1, weight=0)
        root.grid_columnconfigure(2, weight=0)
        root.grid_columnconfigure(3, weight=0)

    def toggle_show_password(self):
        self.password_entry.config(show="" if self.show_password_var.get() else "*")

    def toggle_show_generated_password(self):
        self.generated_password_entry.config(show="" if self.show_generated_var.get() else "*")

    def check_password_strength(self):
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Input Error", "Please enter a password to check.")
            return
        strength, reasons, suggestions = check_strength(password)
        entropy = calculate_entropy(password)
        hashed = hash_password(password)
        save_to_file(password, strength, entropy)
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, f"Password Strength: {strength}\n")
        self.result_text.insert(tk.END, f"Entropy: {entropy} bits\n")
        self.result_text.insert(tk.END, f"SHA-256 Hash: {hashed}\n\n")
        self.result_text.insert(tk.END, "Analysis:\n")
        for reason in reasons:
            self.result_text.insert(tk.END, f" - {reason}\n")
        if "STRONG" not in strength:
            self.result_text.insert(tk.END, "\nSuggestions:\n")
            for suggestion in suggestions:
                self.result_text.insert(tk.END, f" - {suggestion}\n")
        self.result_text.config(state="disabled")

    def generate_password(self):
        try:
            length = int(self.length_var.get())
            if length < 8:
                messagebox.showerror("Invalid Length", "Minimum password length is 8.")
                return
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid number for length.")
            return
        new_password = generate_strong_password(length)
        self.generated_password_var.set(new_password)
        self.generated_password_entry.config(show="" if self.show_generated_var.get() else "*")

    def exit_program(self):
        answer = messagebox.askyesno("Confirm Exit", "Are you sure you want to exit?")
        if answer:
            messagebox.showinfo(
                "Thank you",
                "Thank you for using our tool, we appreciate your trust and remember to keep your passwords safe and updated regularly, "
                "Stay safe online! Feel free to come back anytime to check your passwords."
            )
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordCheckerApp(root)
    root.mainloop()
