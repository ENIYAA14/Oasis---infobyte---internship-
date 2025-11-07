import tkinter as tk
from tkinter import ttk, messagebox
import pandas as pd
import os
import matplotlib.pyplot as plt
from datetime import datetime

DATA_FILE = "bmi_data.csv"


# ----------- BMI Utility Functions -----------
def calculate_bmi(weight, height):
    """Calculate BMI = weight(kg) / [height(m)]²"""
    try:
        height_m = height / 100  # convert cm to meters
        bmi = weight / (height_m ** 2)
        return round(bmi, 2)
    except ZeroDivisionError:
        return 0


def get_bmi_category(bmi):
    """Return BMI category string and color."""
    if bmi == 0:
        return "Invalid", "gray"
    elif bmi < 18.5:
        return "Underweight", "blue"
    elif 18.5 <= bmi < 25:
        return "Normal", "green"
    elif 25 <= bmi < 30:
        return "Overweight", "orange"
    else:
        return "Obese", "red"


def save_bmi_record(name, weight, height, bmi):
    """Append a record to CSV."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    record = pd.DataFrame([{
        "Name": name,
        "Weight (kg)": weight,
        "Height (cm)": height,
        "BMI": bmi,
        "Date": now
    }])
    if not os.path.exists(DATA_FILE):
        record.to_csv(DATA_FILE, index=False)
    else:
        record.to_csv(DATA_FILE, mode="a", header=False, index=False)


def load_user_data(name):
    """Return user's historical BMI records as a DataFrame."""
    if not os.path.exists(DATA_FILE):
        return pd.DataFrame()
    df = pd.read_csv(DATA_FILE)
    return df[df["Name"].str.lower() == name.lower()]


# ----------- GUI Application -----------
class BMICalculatorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced BMI Calculator")
        self.geometry("600x480")
        self.resizable(False, False)
        self.configure(padx=20, pady=20)

        self.create_widgets()

    def create_widgets(self):
        title = ttk.Label(self, text="BMI Calculator", font=("Arial", 20, "bold"))
        title.pack(pady=10)

        # --- User Input Frame ---
        input_frame = ttk.LabelFrame(self, text="Enter Details", padding=10)
        input_frame.pack(fill="x", pady=10)

        ttk.Label(input_frame, text="Name:").grid(row=0, column=0, sticky="w", pady=5)
        self.name_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.name_var, width=30).grid(row=0, column=1)

        ttk.Label(input_frame, text="Weight (kg):").grid(row=1, column=0, sticky="w", pady=5)
        self.weight_var = tk.DoubleVar()
        ttk.Entry(input_frame, textvariable=self.weight_var, width=30).grid(row=1, column=1)

        ttk.Label(input_frame, text="Height (cm):").grid(row=2, column=0, sticky="w", pady=5)
        self.height_var = tk.DoubleVar()
        ttk.Entry(input_frame, textvariable=self.height_var, width=30).grid(row=2, column=1)

        ttk.Button(input_frame, text="Calculate BMI", command=self.calculate_bmi_action).grid(row=3, column=0, columnspan=2, pady=10)

        # --- Result Display ---
        result_frame = ttk.LabelFrame(self, text="Result", padding=10)
        result_frame.pack(fill="x", pady=10)

        ttk.Label(result_frame, text="Your BMI:").grid(row=0, column=0, sticky="w", pady=5)
        self.bmi_result = ttk.Label(result_frame, text="-", font=("Arial", 16, "bold"))
        self.bmi_result.grid(row=0, column=1, sticky="w")

        ttk.Label(result_frame, text="Category:").grid(row=1, column=0, sticky="w", pady=5)
        self.category_label = ttk.Label(result_frame, text="-", font=("Arial", 14, "bold"))
        self.category_label.grid(row=1, column=1, sticky="w")

        # --- Actions ---
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="View History", command=self.show_history).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Show BMI Trend", command=self.show_trend).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text="Exit", command=self.destroy).grid(row=0, column=2, padx=5)

        # --- Status ---
        self.status_label = ttk.Label(self, text="Ready", anchor="w", foreground="gray")
        self.status_label.pack(fill="x", pady=5)

    def calculate_bmi_action(self):
        name = self.name_var.get().strip()
        weight = self.weight_var.get()
        height = self.height_var.get()

        if not name:
            messagebox.showwarning("Input Error", "Please enter your name.")
            return
        if weight <= 0 or height <= 0:
            messagebox.showwarning("Input Error", "Enter valid weight and height.")
            return

        bmi = calculate_bmi(weight, height)
        category, color = get_bmi_category(bmi)

        self.bmi_result.config(text=str(bmi))
        self.category_label.config(text=category, foreground=color)
        self.status_label.config(text=f"Calculated BMI for {name}")

        save_bmi_record(name, weight, height, bmi)
        messagebox.showinfo("BMI Result", f"{name}, your BMI is {bmi} ({category})")

    def show_history(self):
        name = self.name_var.get().strip()
        if not name:
            messagebox.showwarning("Input Error", "Enter a name to view history.")
            return

        data = load_user_data(name)
        if data.empty:
            messagebox.showinfo("No Data", f"No records found for {name}.")
            return

        # Create a popup window
        win = tk.Toplevel(self)
        win.title(f"{name}'s BMI History")
        win.geometry("500x300")

        cols = list(data.columns)
        tree = ttk.Treeview(win, columns=cols, show="headings")
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=100)
        for _, row in data.iterrows():
            tree.insert("", tk.END, values=list(row))
        tree.pack(fill="both", expand=True)

    def show_trend(self):
        name = self.name_var.get().strip()
        if not name:
            messagebox.showwarning("Input Error", "Enter a name to view trend.")
            return

        data = load_user_data(name)
        if data.empty:
            messagebox.showinfo("No Data", f"No records found for {name}.")
            return

        data["Date"] = pd.to_datetime(data["Date"])
        plt.figure(figsize=(7, 4))
        plt.plot(data["Date"], data["BMI"], marker="o", label=f"{name}'s BMI")
        plt.title(f"{name}'s BMI Trend")
        plt.xlabel("Date")
        plt.ylabel("BMI")
        plt.grid(True)
        plt.legend()
        plt.tight_layout()
        plt.show()


# ----------- Run the App -----------
if __name__ == "__main__":
    app = BMICalculatorApp()
    app.mainloop()
