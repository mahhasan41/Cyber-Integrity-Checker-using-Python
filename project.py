import hashlib
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import os

class CyberVaultIntegrityChecker(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("CyberVault Integrity Checker with Real-Time Monitoring")
        self.geometry("700x550")
        self.resizable(False, False)
        self.configure(bg="#2C3E50")

        # Variables
        self.file_path_var = tk.StringVar()
        self.algo_var = tk.StringVar(value="sha512")
        self.result_var = tk.StringVar()
        self.original_hash_var = tk.StringVar()
        self.monitoring = False
        self.monitored_hash = None

        self._setup_styles()
        self._create_widgets()

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure("TLabel", background="#2C3E50", foreground="#ECF0F1", font=("Segoe UI", 12))
        style.configure("TEntry", font=("Segoe UI", 11))
        style.configure("TButton", font=("Segoe UI Semibold", 11), padding=8)
        style.map("TButton",
                  background=[("active", "#34495E"), ("!disabled", "#2980B9")],
                  foreground=[("active", "white"), ("!disabled", "white")])
        style.configure("Result.TLabel", background="#ECF0F1", foreground="#34495E", font=("Consolas", 11, "bold"),
                        relief="solid", padding=10)
        style.configure("TCombobox", font=("Segoe UI", 11))

    def _create_widgets(self):
        header = ttk.Label(self, text="CyberVault Hash Integrity Tool", font=("Segoe UI", 18, "bold"))
        header.pack(pady=(20, 15))

        # File Selection
        file_frame = ttk.Frame(self)
        file_frame.pack(fill="x", padx=30, pady=10)
        ttk.Label(file_frame, text="Select a File:").pack(side="left", padx=(0, 10))
        file_entry = ttk.Entry(file_frame, textvariable=self.file_path_var, width=45)
        file_entry.pack(side="left", fill="x", expand=True)
        browse_btn = ttk.Button(file_frame, text="Browse", command=self.browse_file)
        browse_btn.pack(side="left", padx=10)

        # Algorithm Selection
        algo_frame = ttk.Frame(self)
        algo_frame.pack(fill="x", padx=30, pady=10)
        ttk.Label(algo_frame, text="Select Algorithm:").pack(side="left", padx=(0, 10))
        algo_combo = ttk.Combobox(algo_frame, textvariable=self.algo_var,
                                  values=["sha512", "md5", "sha256", "sha1"], state="readonly", width=15)
        algo_combo.pack(side="left")
        algo_combo.current(0)

        # Generate Hash Button
        gen_btn = ttk.Button(self, text="Generate Hash", command=self.generate_hash_gui)
        gen_btn.pack(pady=(15, 10))

        # Result Display
        result_label = ttk.Label(self, textvariable=self.result_var, style="Result.TLabel", anchor="w", justify="left",
                                 wraplength=620)
        result_label.pack(fill="x", padx=30)

        # Copy to Clipboard Button
        copy_btn = ttk.Button(self, text="Copy Hash to Clipboard", command=self.copy_to_clipboard)
        copy_btn.pack(pady=10)

        # Original Hash Input
        orig_hash_frame = ttk.Frame(self)
        orig_hash_frame.pack(fill="x", padx=30, pady=10)
        ttk.Label(orig_hash_frame, text="Original Hash Value:").pack(side="left", padx=(0, 10))
        orig_entry = ttk.Entry(orig_hash_frame, textvariable=self.original_hash_var, width=60)
        orig_entry.pack(side="left", fill="x", expand=True)

        # Check Integrity Button
        check_btn = ttk.Button(self, text="Check Integrity", command=self.check_integrity)
        check_btn.pack(pady=10)

        # Monitor Toggle Button
        self.monitor_btn = ttk.Button(self, text="Start Real-Time Monitoring", command=self.toggle_monitoring)
        self.monitor_btn.pack(pady=10)

        # Status Bar
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w", background="#34495E",
                               foreground="#ECF0F1", font=("Segoe UI", 10))
        status_bar.pack(side="bottom", fill="x")

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path_var.set(path)
            self.status_var.set(f"Selected file: {path}")

    def generate_hash(self, file_path, algorithm='sha512'):
        try:
            with open(file_path, 'rb') as file:
                hasher = hashlib.new(algorithm)
                while chunk := file.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except FileNotFoundError:
            return None
        except ValueError:
            return None

    def generate_hash_gui(self):
        file_path = self.file_path_var.get()
        algorithm = self.algo_var.get()
        if not file_path:
            self.status_var.set("Error: No file selected.")
            self.result_var.set("")
            return
        hash_val = self.generate_hash(file_path, algorithm)
        if hash_val:
            self.result_var.set(f"Hash ({algorithm}):\n{hash_val}")
            self.status_var.set("Hash generated successfully.")
        else:
            self.result_var.set("")
            self.status_var.set("Error generating hash. Check the file or algorithm.")

    def copy_to_clipboard(self):
        current_text = self.result_var.get()
        if current_text and "Hash" in current_text:
            hash_value = current_text.split("\n", 1)[1]
            self.clipboard_clear()
            self.clipboard_append(hash_value)
            self.status_var.set("Hash copied to clipboard!")
        else:
            self.status_var.set("No hash to copy.")

    def check_integrity(self):
        original = self.original_hash_var.get().strip()
        current_text = self.result_var.get()
        if not original:
            self.status_var.set("Please enter the original hash value.")
            return
        if current_text and "Hash" in current_text:
            generated = current_text.split("\n", 1)[1].strip()
            if original == generated:
                self.status_var.set("Integrity Check Passed: File is NOT modified.")
                messagebox.showinfo("Integrity Check", "File is NOT modified.")
            else:
                self.status_var.set("Integrity Check Failed: File is modified.")
                messagebox.showwarning("Integrity Check", "File is MODIFIED!")
        else:
            self.status_var.set("Please generate the hash before checking integrity.")

    def toggle_monitoring(self):
        if self.monitoring:
            self.monitoring = False
            self.monitor_btn.config(text="Start Real-Time Monitoring")
            self.status_var.set("Stopped real-time monitoring.")
        else:
            file_path = self.file_path_var.get()
            if not file_path:
                self.status_var.set("Select a file to monitor.")
                return
            algo = self.algo_var.get()
            initial_hash = self.generate_hash(file_path, algo)
            if not initial_hash:
                self.status_var.set("Cannot hash selected file.")
                return
            self.monitored_hash = initial_hash
            self.monitoring = True
            self.monitor_btn.config(text="Stop Real-Time Monitoring")
            self.status_var.set(f"Started monitoring '{os.path.basename(file_path)}'.")
            self.after(5000, self.monitor_file)  # check every 5 seconds

    def monitor_file(self):
        if not self.monitoring:
            return

        file_path = self.file_path_var.get()
        algo = self.algo_var.get()
        current_hash = self.generate_hash(file_path, algo)

        if current_hash is None:
            self.status_var.set("File missing or unreadable during monitoring.")
            self.monitoring = False
            self.monitor_btn.config(text="Start Real-Time Monitoring")
            return

        if current_hash != self.monitored_hash:
            self.status_var.set(f"ALERT: File '{os.path.basename(file_path)}' was modified!")
            messagebox.showwarning("File Modification Detected",
                                   f"File '{os.path.basename(file_path)}' has been modified!")
            self.monitored_hash = current_hash  # update to new hash

        # schedule next check
        if self.monitoring:
            self.after(5000, self.monitor_file)

if __name__ == "__main__":
    app = CyberVaultIntegrityChecker()
    app.mainloop()
