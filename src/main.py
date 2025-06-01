import tkinter as tk

from src.config import create_cipher, create_database
from src.password_manager import PasswordManagerGui

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Password Manager")
    root.geometry("600x400")
    root.update_idletasks()
    window_width = root.winfo_width()
    window_height = root.winfo_height()
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x_offset = (screen_width // 2) - (window_width // 2)
    y_offset = (screen_height // 2) - (window_height // 2)
    root.geometry(f"{window_width}x{window_height}+{x_offset}+{y_offset}")

    cipher = create_cipher()
    cursor, conn = create_database()

    pm = PasswordManagerGui(root, cipher, conn, cursor)
    pm.run()
