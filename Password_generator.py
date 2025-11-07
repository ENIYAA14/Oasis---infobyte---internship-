import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import string
import secrets
import math
import sys

# ---------- Utility / Generation logic ----------

AMBIGUOUS = {'l', 'I', '1', 'O', '0', 'o'}

SYMBOLS_COMMON = "!@#$%^&*()-_=+[]{};:,.<>/?\\|`~"

def build_charset(use_lower, use_upper, use_digits, use_symbols, exclude_ambiguous):
    chars = []
    if use_lower:
        chars.extend(string.ascii_lowercase)
    if use_upper:
        chars.extend(string.ascii_uppercase)
    if use_digits:
        chars.extend(string.digits)
    if use_symbols:
        chars.extend(SYMBOLS_COMMON)
    if exclude_ambiguous:
        chars = [c for c in chars if c not in AMBIGUOUS]
    return ''.join(sorted(set(chars)))  # remove duplicates and sort for determinism

def has_sequence(s, seq_len=3):
    """
    Detects simple ascending or descending sequences of letters or digits
    of length >= seq_len. e.g., 'abc', '234', 'cba', '432'
    """
    if len(s) < seq_len:
        return False
    # map letters to numeric positions
    vals = []
    for ch in s:
        if ch.isdigit():
            vals.append(ord(ch) - ord('0'))
        elif ch.isalpha():
            # normalize letters to lowercase
            vals.append(ord(ch.lower()) - ord('a') + 10)  # offset so digits and letters distinct but monotonic
        else:
            vals.append(None)  # symbols break sequences

    # scan windows
    for i in range(len(vals) - seq_len + 1):
        window = vals[i:i+seq_len]
        if any(v is None for v in window):
            continue
        # check ascending
        asc = all(window[j+1] - window[j] == 1 for j in range(len(window)-1))
        desc = all(window[j] - window[j+1] == 1 for j in range(len(window)-1))
        if asc or desc:
            return True
    return False

def calculate_entropy(pool_size, length):
    """Return entropy in bits (float)."""
    if pool_size <= 0 or length <= 0:
        return 0.0
    return length * math.log2(pool_size)

def strength_label_from_entropy(entropy_bits):
    """Give a human-friendly strength label from entropy bits."""
    if entropy_bits < 28:
        return "Very Weak"
    if entropy_bits < 36:
        return "Weak"
    if entropy_bits < 60:
        return "Reasonable"
    if entropy_bits < 80:
        return "Strong"
    return "Very Strong"

def generate_single_password(length, charset,
                             require_each_classes=None,
                             avoid_repeats=True,
                             avoid_sequences=True,
                             max_attempts=1000):
    """
    Generate a single password under constraints. Uses secrets.choice for security.
    - charset: string of allowed characters
    - require_each_classes: list of strings (each string is allowed chars for that class)
    - avoid_repeats: if True, disallow immediate repeats of the same char more than twice
    - avoid_sequences: if True, reject passwords that contain simple sequences
    """
    if not charset:
        raise ValueError("Character set is empty. Enable at least one class.")
    if require_each_classes is None:
        require_each_classes = []

    # quick pool size
    pool = len(charset)
    attempts = 0
    while attempts < max_attempts:
        attempts += 1
        # Start by ensuring one char from each required class if possible
        password_chars = []
        for cls in require_each_classes:
            # cls may share chars with charset; choose from intersection
            available = [c for c in cls if c in charset]
            if not available:
                # impossible to satisfy requirement
                raise ValueError("Requirement cannot be satisfied: class {} has no available characters in charset".format(cls))
            password_chars.append(secrets.choice(available))

        # Fill rest
        while len(password_chars) < length:
            ch = secrets.choice(charset)
            # optional: avoid too many immediate repeats: no more than 2 same char consecutively
            if avoid_repeats and len(password_chars) >= 2 and password_chars[-1] == password_chars[-2] == ch:
                continue
            password_chars.append(ch)

        # shuffle to distribute guaranteed-class chars
        secrets.SystemRandom().shuffle(password_chars)
        candidate = ''.join(password_chars)

        # check for sequences
        if avoid_sequences and has_sequence(candidate, seq_len=3):
            continue

        # ensure each required class exists
        ok = True
        for cls in require_each_classes:
            if not any(c in cls for c in candidate):
                ok = False
                break
        if not ok:
            continue

        # All checks passed
        return candidate

    raise RuntimeError("Failed to generate password that meets constraints after {} attempts".format(max_attempts))


# ---------- GUI ----------

class PasswordGeneratorGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Password Generator")
        self.geometry("820x520")
        self.resizable(True, True)

        self.create_variables()
        self.create_widgets()
        self.update_charset_preview()

    def create_variables(self):
        # Options
        self.length_var = tk.IntVar(value=16)
        self.count_var = tk.IntVar(value=5)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_upper = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        self.exclude_ambiguous = tk.BooleanVar(value=True)
        self.avoid_repeats = tk.BooleanVar(value=True)
        self.avoid_sequences = tk.BooleanVar(value=True)
        self.auto_copy = tk.BooleanVar(value=False)
        self.last_generated = []

    def create_widgets(self):
        # Main frame
        frm = ttk.Frame(self, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        # Left control panel
        left = ttk.Frame(frm)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0,12))

        # Length
        length_label = ttk.Label(left, text="Password length:")
        length_label.grid(row=0, column=0, sticky="w")
        length_spin = ttk.Spinbox(left, from_=4, to=128, textvariable=self.length_var, width=6)
        length_spin.grid(row=0, column=1, sticky="w", padx=6)

        # Count
        count_label = ttk.Label(left, text="Count (generate):")
        count_label.grid(row=1, column=0, sticky="w")
        count_spin = ttk.Spinbox(left, from_=1, to=50, textvariable=self.count_var, width=6)
        count_spin.grid(row=1, column=1, sticky="w", padx=6)

        # Character sets
        cs_label = ttk.Label(left, text="Character sets:")
        cs_label.grid(row=2, column=0, columnspan=2, pady=(8,0), sticky="w")
        ttk.Checkbutton(left, text="Lowercase (a-z)", variable=self.use_lower, command=self.update_charset_preview).grid(row=3, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(left, text="Uppercase (A-Z)", variable=self.use_upper, command=self.update_charset_preview).grid(row=4, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(left, text="Digits (0-9)", variable=self.use_digits, command=self.update_charset_preview).grid(row=5, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(left, text="Symbols", variable=self.use_symbols, command=self.update_charset_preview).grid(row=6, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(left, text="Exclude ambiguous (e.g. l,1,O,0)", variable=self.exclude_ambiguous, command=self.update_charset_preview).grid(row=7, column=0, columnspan=2, sticky="w", pady=(0,6))

        # Security rules
        sec_label = ttk.Label(left, text="Security rules:")
        sec_label.grid(row=8, column=0, columnspan=2, pady=(8,0), sticky="w")
        ttk.Checkbutton(left, text="Avoid immediate triple repeats (e.g., 'aaa')", variable=self.avoid_repeats).grid(row=9, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(left, text="Avoid simple sequences (abc, 123)", variable=self.avoid_sequences).grid(row=10, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(left, text="Auto-copy generated (last one)", variable=self.auto_copy).grid(row=11, column=0, columnspan=2, sticky="w")

        # Charset preview and entropy
        ttk.Separator(left, orient=tk.HORIZONTAL).grid(row=12, column=0, columnspan=2, sticky="ew", pady=8)
        ttk.Label(left, text="Charset preview:").grid(row=13, column=0, columnspan=2, sticky="w")
        self.charset_preview = tk.Text(left, width=24, height=4, wrap="word", state="disabled")
        self.charset_preview.grid(row=14, column=0, columnspan=2, pady=(4,6))

        # Buttons
        gen_btn = ttk.Button(left, text="Generate", command=self.on_generate)
        gen_btn.grid(row=15, column=0, sticky="ew", pady=(6,0))
        copy_btn = ttk.Button(left, text="Copy Selected", command=self.on_copy_selected)
        copy_btn.grid(row=15, column=1, sticky="ew", padx=(6,0), pady=(6,0))
        save_btn = ttk.Button(left, text="Save to File...", command=self.on_save_to_file)
        save_btn.grid(row=16, column=0, columnspan=2, sticky="ew", pady=(6,0))

        # Right area: results and details
        right = ttk.Frame(frm)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Strength and info
        info_frame = ttk.Frame(right)
        info_frame.pack(fill=tk.X, pady=(0,8))
        self.entropy_var = tk.StringVar(value="Entropy: 0 bits")
        self.strength_var = tk.StringVar(value="Strength: -")
        ttk.Label(info_frame, textvariable=self.entropy_var).pack(side=tk.LEFT, padx=(0,8))
        ttk.Label(info_frame, textvariable=self.strength_var).pack(side=tk.LEFT)

        # Results listbox with scrollbar
        results_frame = ttk.Frame(right)
        results_frame.pack(fill=tk.BOTH, expand=True)
        self.results_list = tk.Listbox(results_frame, font=("Consolas", 12))
        self.results_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_list.yview)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y)
        self.results_list.config(yscrollcommand=scrollbar.set)
        self.results_list.bind("<Double-Button-1>", lambda e: self.on_copy_selected())

        # Bottom status
        status_frame = ttk.Frame(right)
        status_frame.pack(fill=tk.X, pady=(8,0))
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT)

        # Preset buttons
        presets_frame = ttk.Frame(right)
        presets_frame.pack(fill=tk.X, pady=(8,0))
        ttk.Label(presets_frame, text="Presets:").pack(side=tk.LEFT, padx=(0,8))
        ttk.Button(presets_frame, text="Website (12)", command=lambda: self.apply_preset(length=12, lower=True, upper=True, digits=True, symbols=True)).pack(side=tk.LEFT, padx=4)
        ttk.Button(presets_frame, text="High-security (24)", command=lambda: self.apply_preset(length=24, lower=True, upper=True, digits=True, symbols=True)).pack(side=tk.LEFT, padx=4)
        ttk.Button(presets_frame, text="PIN (6 digits)", command=lambda: self.apply_preset(length=6, lower=False, upper=False, digits=True, symbols=False)).pack(side=tk.LEFT, padx=4)

        # Keyboard bindings
        self.bind_all("<Control-g>", lambda e: self.on_generate())
        self.bind_all("<Control-c>", lambda e: self.on_copy_selected())

    def apply_preset(self, length, lower, upper, digits, symbols):
        self.length_var.set(length)
        self.use_lower.set(lower)
        self.use_upper.set(upper)
        self.use_digits.set(digits)
        self.use_symbols.set(symbols)
        self.update_charset_preview()

    def update_charset_preview(self):
        cs = build_charset(self.use_lower.get(), self.use_upper.get(), self.use_digits.get(),
                           self.use_symbols.get(), self.exclude_ambiguous.get())
        # update display
        self.charset_preview.configure(state="normal")
        self.charset_preview.delete("1.0", tk.END)
        if cs:
            # show first N chars then "..." if large
            preview = cs if len(cs) <= 150 else (cs[:150] + " ...")
            self.charset_preview.insert(tk.END, preview)
        else:
            self.charset_preview.insert(tk.END, "(empty) — enable at least one class")
        self.charset_preview.configure(state="disabled")

        # update entropy preview for current length and pool
        pool_size = len(cs)
        length = max(1, self.length_var.get())
        bits = calculate_entropy(pool_size, length) if pool_size > 0 else 0.0
        self.entropy_var.set(f"Entropy: {bits:.1f} bits (pool={pool_size})")
        self.strength_var.set(f"Strength: {strength_label_from_entropy(bits)}")

    def on_generate(self):
        try:
            length = int(self.length_var.get())
        except Exception:
            messagebox.showerror("Input error", "Password length must be an integer.")
            return
        count = max(1, min(100, int(self.count_var.get())))
        cs = build_charset(self.use_lower.get(), self.use_upper.get(), self.use_digits.get(),
                           self.use_symbols.get(), self.exclude_ambiguous.get())
        if not cs:
            messagebox.showerror("No charset", "No characters available. Enable at least one character class.")
            return

        # build required classes list to guarantee at least one from each selected set
        required = []
        if self.use_lower.get():
            required.append(string.ascii_lowercase)
        if self.use_upper.get():
            required.append(string.ascii_uppercase)
        if self.use_digits.get():
            required.append(string.digits)
        if self.use_symbols.get():
            required.append(SYMBOLS_COMMON)

        # adjust required classes to reflect exclude_ambiguous
        if self.exclude_ambiguous.get():
            required = [''.join([c for c in r if c not in AMBIGUOUS]) for r in required]

        # generate count passwords
        results = []
        errors = []
        for i in range(count):
            try:
                pw = generate_single_password(
                    length=length,
                    charset=cs,
                    require_each_classes=required,
                    avoid_repeats=self.avoid_repeats.get(),
                    avoid_sequences=self.avoid_sequences.get()
                )
                results.append(pw)
            except Exception as e:
                errors.append(str(e))
                break

        if errors:
            messagebox.showerror("Generation error", "\n".join(errors))
            self.status_var.set("Error")
            return

        # populate results listbox
        self.results_list.delete(0, tk.END)
        for pw in results:
            self.results_list.insert(tk.END, pw)
        self.last_generated = results

        # update entropy display using current pool
        pool_size = len(cs)
        bits = calculate_entropy(pool_size, length)
        self.entropy_var.set(f"Entropy: {bits:.1f} bits (pool={pool_size})")
        self.strength_var.set(f"Strength: {strength_label_from_entropy(bits)}")

        self.status_var.set(f"Generated {len(results)} password(s).")
        # optionally auto-copy the first one
        if self.auto_copy.get() and results:
            self.copy_to_clipboard(results[0])
            self.status_var.set(self.status_var.get() + " (Copied first to clipboard)")

    def on_copy_selected(self):
        selection = self.results_list.curselection()
        if not selection:
            # if nothing selected, copy the first result if available
            if self.last_generated:
                to_copy = self.last_generated[0]
            else:
                messagebox.showinfo("Nothing to copy", "No password selected and none generated yet.")
                return
        else:
            idx = selection[0]
            to_copy = self.results_list.get(idx)

        self.copy_to_clipboard(to_copy)
        self.status_var.set("Copied to clipboard")

    def copy_to_clipboard(self, text):
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            # also keep clipboard available after app closes on some platforms
            self.update()  # now it stays on clipboard
        except Exception as e:
            messagebox.showerror("Clipboard error", f"Failed to copy to clipboard: {e}")

    def on_save_to_file(self):
        if not self.last_generated:
            messagebox.showinfo("No passwords", "Generate passwords before saving.")
            return
        fpath = filedialog.asksaveasfilename(
            title="Save passwords",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not fpath:
            return
        try:
            with open(fpath, "w", encoding="utf-8") as f:
                f.write("# Generated passwords\n")
                f.write(f"# Count: {len(self.last_generated)}\n")
                f.write(f"# Length: {self.length_var.get()}\n\n")
                for pw in self.last_generated:
                    f.write(pw + "\n")
            self.status_var.set(f"Saved {len(self.last_generated)} passwords to {fpath}")
        except Exception as e:
            messagebox.showerror("Save error", f"Failed to save file: {e}")

# ---------- Run app ----------

def main():
    app = PasswordGeneratorGUI()
    # Update preview initially
    app.update_charset_preview()
    app.mainloop()

if __name__ == "__main__":
    main()
