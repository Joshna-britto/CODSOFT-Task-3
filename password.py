import tkinter as tk
from tkinter import ttk, messagebox
import string, secrets

class SmartPasswordGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Smart Password Generator")
        self.root.geometry("400x420")
        self.root.resizable(False, False)

        style = ttk.Style()
        style.configure("TLabel", font=("Arial", 12))
        style.configure("TButton", font=("Arial", 12), padding=5)

        ttk.Label(root, text="Password Length:").pack(pady=(20, 5))
        self.length_var = tk.IntVar(value=12)
        ttk.Entry(root, textvariable=self.length_var, width=10, font=("Arial", 12)).pack()

        self.use_upper = tk.BooleanVar(value=True)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)

        ttk.Checkbutton(root, text="Include Uppercase (A-Z)", variable=self.use_upper).pack(anchor="w", padx=50)
        ttk.Checkbutton(root, text="Include Lowercase (a-z)", variable=self.use_lower).pack(anchor="w", padx=50)
        ttk.Checkbutton(root, text="Include Numbers (0-9)", variable=self.use_digits).pack(anchor="w", padx=50)
        ttk.Checkbutton(root, text="Include Symbols (!@#...)", variable=self.use_symbols).pack(anchor="w", padx=50)

        ttk.Button(root, text="Generate Password", command=self.generate_password).pack(pady=15)

        ttk.Label(root, text="Generated Password:").pack()
        self.password_entry = ttk.Entry(root, width=40, font=("Consolas", 13), justify="center")
        self.password_entry.pack(pady=5, ipady=4)

        ttk.Button(root, text="Copy to Clipboard", command=self.copy_to_clipboard).pack(pady=5)
        ttk.Button(root, text="Clear", command=lambda: self.password_entry.delete(0, tk.END)).pack()

        self.strength_label = ttk.Label(root, text="Password Strength: N/A", foreground="gray")
        self.strength_label.pack(pady=10)

    def generate_password(self):
        try:
            length = int(self.length_var.get())
            if length < 4 or length > 50:
                messagebox.showwarning("Warning", "Length should be between 4 and 50.")
                return

            char_pool = ""
            if self.use_upper.get():
                char_pool += string.ascii_uppercase
            if self.use_lower.get():
                char_pool += string.ascii_lowercase
            if self.use_digits.get():
                char_pool += string.digits
            if self.use_symbols.get():
                char_pool += string.punctuation

            if not char_pool:
                messagebox.showerror("Error", "Select at least one character set!")
                return

            password = ''.join(secrets.choice(char_pool) for _ in range(length))
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, password)

            self.check_strength(password)

        except Exception as e:
            messagebox.showerror("Error", f"Something went wrong:\n{e}")

    def copy_to_clipboard(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showinfo("Info", "No password to copy.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

    def check_strength(self, password):
        length = len(password)
        categories = sum([
            any(c.isupper() for c in password),
            any(c.islower() for c in password),
            any(c.isdigit() for c in password),
            any(c in string.punctuation for c in password)
        ])

        # Simple heuristic for strength
        if length < 8 or categories < 2:
            strength = "Weak"
            color = "red"
        elif length < 12 or categories < 3:
            strength = "Medium"
            color = "orange"
        else:
            strength = "Strong"
            color = "green"

        self.strength_label.config(text=f"Password Strength: {strength}", foreground=color)

root = tk.Tk()
app = SmartPasswordGenerator(root)
root.mainloop()
