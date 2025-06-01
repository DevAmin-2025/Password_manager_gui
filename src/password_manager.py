import secrets
import sqlite3
import string
import tkinter as tk
import tkinter.font as tkfont
from tkinter import messagebox


class PasswordManagerGui:
    """
    A graphical user interface for a password manager, built with Tkinter.

    This class provides user registration, login, password management, and encryption integration using Fernet.

    Attributes:
        root: The main Tkinter window.
        cipher: The encryption tool used for password security.
        conn: Database connection.
        cursor: Database cursor for executing queries.
        current_action: Stores the current action (register/login).
        current_user: The currently logged-in user.
        password_visible: Tracks password visibility toggle.
        custom_font: Custom font for UI elements.
    """
    def __init__(self, root, cipher, conn, cursor):
        self.root = root
        self.cipher = cipher
        self.conn = conn
        self.cursor = cursor
        self.current_action = ""
        self.current_user = ""
        self.password_visible = tk.BooleanVar()
        self.custom_font = tkfont.Font(family="Arial", size=12)
        self.setup_ui()

    def setup_ui(self):
        """Set up the main UI components for the password manager."""
        # Show register btn
        self.register_btn = tk.Button(
            self.root, text="Register", font=self.custom_font, width=20, command=self.show_register
            )
        self.register_btn.pack(pady=(130, 0), anchor="n")

        # Show login btn
        self.login_btn = tk.Button(
            self.root, text="Login", width=20, font=self.custom_font, command=self.show_login
            )
        self.login_btn.pack(pady=10)

        # Show register and login fields (hidden initially)
        self.username_label = tk.Label(self.root, font=self.custom_font, text="Username:")
        self.username_entry = tk.Entry(self.root)
        self.password_label = tk.Label(self.root, font=self.custom_font, text="Password (leave empty to generate strong password):")
        self.password_entry = tk.Entry(self.root, show="*")
        self.submit_btn = tk.Button(self.root, text="Submit", font=self.custom_font, width=20, command=self.process_action)
        self.login_password_label = tk.Label(self.root, text="Password:", font=self.custom_font)

        # Back btn (hidden initially)
        self.back_btn = tk.Button(self.root, text="Back", font=self.custom_font, width=20, comman=self.show_main_menu)

        # Toggle password visibility
        self.toggle_visibility = tk.Checkbutton(
            self.root,
            text="Show Password",
            font=self.custom_font,
            variable=self.password_visible,
            command=self.toggle_password
        )

        # Change password btn (hidden initially)
        self.change_password_btn = tk.Button(
            self.root, text="Change Password", font=self.custom_font, width=20, command=self.show_change_password
            )

        # Change password fields (hidden initially)
        self.new_password_label = tk.Label(self.root, font=self.custom_font, text="New password (leave empty to generate strong password):")
        self.new_password_entry = tk.Entry(self.root, show="*")
        self.change_password_submit = tk.Button(
            self.root, text="Update Password", width=20, font=self.custom_font, command=self.change_password
            )

        # Back to dashboard btn
        self.back_dashboard_btn = tk.Button(self.root, text="Back", font=self.custom_font, width=20, command=self.show_user_dashboard)

        # Add password btn (hidden initially)
        self.add_password_btn = tk.Button(self.root, text="Add Password", font=self.custom_font, width=20, command=self.show_add_password)

        # Add password fields (hidden initially)
        self.website_name_label = tk.Label(self.root, font=self.custom_font, text="Name of the website/service:")
        self.website_name_entry = tk.Entry(self.root)
        self.website_username_label = tk.Label(self.root, font=self.custom_font, text="Username for the website/service:")
        self.website_username_entry = tk.Entry(self.root)
        self.website_password_label = tk.Label(self.root, font=self.custom_font, text="Password (leave empty to generate strong password):")
        self.website_password_entry = tk.Entry(self.root, show="*")
        self.add_password_submit = tk.Button(self.root, text="Submit", font=self.custom_font, width=20, command=self.add_password)

        # Change website password btn (hidden initially)
        self.change_website_password_btn = tk.Button(
            self.root, text="Change Website-password", font=self.custom_font, width=20, command=self.show_change_website_password
            )

        # Change website password fields (hidden initially)
        self.change_website_password_label = tk.Label(
            self.root, font=self.custom_font, text="New password (leave empty to generate strong password):"
            )
        self.change_website_password_entry = tk.Entry(self.root, show="*")
        self.change_website_password_submit = tk.Button(
            self.root, text="Submit", width=20, font=self.custom_font, command=self.change_website_password
            )

        # Change website username btn (hidden initially)
        self.change_website_username_btn = tk.Button(
            self.root, text="Change Website-username", font=self.custom_font, width=20, command=self.show_change_website_username
            )

        # Change website username fields (hidden initially)
        self.change_website_username_label = tk.Label(self.root, font=self.custom_font, text="New username:")
        self.change_website_username_entry = tk.Entry(self.root)
        self.change_website_username_submit = tk.Button(
            self.root, text="Submit", width=20, font=self.custom_font, command=self.change_website_username
            )

        # Delete password btn (hidden initially)
        self.delete_password_btn = tk.Button(
            self.root, text="Delete Password", width=20, font=self.custom_font, command=self.show_delete_password
            )

        # Delete password fields (hidden initially)
        self.website_name_label = tk.Label(self.root, font=self.custom_font, text="Name of the website/service:")
        self.website_name_entry = tk.Entry(self.root)
        self.delete_password_submit = tk.Button(self.root, text="Submit", width=20, font=self.custom_font, command=self.delete_password)

        # View passwords btn (hidden initially)
        self.view_passwords_btn = tk.Button(self.root, text="View Passwords", width=20, font=self.custom_font, command=self.show_view_passwords)

        # View passwords btn (hidden initially)
        self.view_passwords_submit = tk.Button(self.root, text="Show My Passwords", width=20, font=self.custom_font, command=self.view_passwords)

    def hide_all_widgets(self):
        """Hide all widgets from the current UI layout."""
        for widget in self.root.pack_slaves():
            widget.pack_forget()

    def toggle_password(self):
        """
        Toggle password visibility across multiple entry fields.

        If checked, passwords become visible; otherwise, they are hidden.
        """
        char = "" if self.password_visible.get() else "*"
        self.password_entry.config(show=char)
        self.new_password_entry.config(show=char)
        self.website_password_entry.config(show=char)
        self.change_website_password_entry.config(show=char)

    def show_main_menu(self):
        """Display the main menu, showing the register and login buttons."""
        self.hide_all_widgets()
        self.register_btn.pack(pady=(130, 0), anchor="n")
        self.login_btn.pack(pady=10)

    def generate_strong_password(self, length: int = 12) -> string:
        """
        Generate a strong, random password.

        :param length: Length of the password (default is 12 characters).
        :return: A randomly generated password string.
        """
        char = string.ascii_letters + string.digits + string.punctuation
        return "".join(secrets.choice(char) for _ in range(length))

    def show_password(self, password: str):
        """
        Display a popup window with the generated password.

        :param password: The generated password to be displayed.
        """
        popup = tk.Toplevel()
        popup.title("Generated Password")
        popup.geometry("300x100")
        popup.update_idletasks()

        def adjust_position():
            popup_width = popup.winfo_width()
            popup_height = popup.winfo_height()
            screen_width = popup.winfo_screenwidth()
            screen_height = popup.winfo_screenheight()
            x_offset = (screen_width // 2) - (popup_width // 2)
            y_offset = (screen_height // 2) - (popup_height // 2)
            popup.geometry(f"{popup_width}x{popup_height}+{x_offset}+{y_offset}")

        popup.after(150, adjust_position)
        entry = tk.Entry(popup, justify="center")
        entry.insert(0, password)
        entry.config(state="readonly")
        entry.pack(pady=10)

        # Copy btn
        def copy_to_clipboard():
            popup.clipboard_append(password)
            popup.update()
            copy_btn.config(text="Copied")

        copy_btn = tk.Button(popup, text="Copy", font=self.custom_font, command=copy_to_clipboard)
        copy_btn.pack(pady=10)

    def get_user_id(self, name: str) -> int:
        """
        Retrieve the user ID from the database based on the username.

        :param name: The username for which to retrieve the user ID.
        :return: The user ID associated with the username.
        """
        self.cursor.execute(
            "SELECT user_id FROM users WHERE name = ?",
            (name,)
            )
        user = self.cursor.fetchone()
        user_id = user[0]
        return user_id

    def show_register(self):
        """
        Display the registration form for new users.

        Present fields for username and password, along with a visibility toggle and submit button.
        """
        self.current_action = "register"
        self.hide_all_widgets()
        self.username_label.pack(pady=10)
        self.username_entry.pack(pady=10)
        self.password_label.pack(pady=10)
        self.password_entry.pack(pady=10)
        self.toggle_visibility.pack(pady=10)
        self.submit_btn.pack(pady=10)
        self.back_btn.pack(pady=10)

    def show_login(self):
        """
        Display the login form for returning users.

        Present fields for username and password, along with a visibility toggle and submit button.
        """
        self.current_action = "login"
        self.hide_all_widgets()
        self.username_label.pack(pady=10)
        self.username_entry.pack(pady=10)
        self.login_password_label.pack(pady=10)
        self.password_entry.pack(pady=10)
        self.toggle_visibility.pack(pady=10)
        self.submit_btn.pack(pady=10)
        self.back_btn.pack(pady=10)

    def reset_entry(self, *args):
        """
        Clear all text from the specified entry fields.

        :param args: Entry widgets to reset.
        """
        for entry in args:
            entry.delete(0, tk.END)

    def process_action(self):
        """
        Processe user registration or login based on the selected action.

        Ensure input validation, encrypts passwords upon registration, and
        verifie login credentials securely.
        """
        name = self.username_entry.get()
        password = self.password_entry.get()
        if not name.strip():
            messagebox.showerror("Error", "Username can not be empty")
            return
        if self.current_action == "register":
            show_pass = False
            if not password.strip():
                password = self.generate_strong_password()
                show_pass = True
            encrypted_password = self.cipher.encrypt(password.encode()).decode()
            try:
                self.cursor.execute("INSERT INTO users (name, password) VALUES (?, ?)", (name, encrypted_password))
                self.conn.commit()
                messagebox.showinfo("Success", "User registered successfully!")
                if show_pass:
                    self.show_password(password)
                self.show_main_menu()
            except sqlite3.IntegrityError:
                messagebox.showerror("Error", "Username already exists! Please choose a differenct name.")
        if self.current_action == "login":
            if not password.strip():
                messagebox.showerror("Error", "Password can not be empty")
                return
            self.cursor.execute("SELECT password FROM users WHERE name = ?", (name,))
            user = self.cursor.fetchone()
            if user:
                decrypted_password = self.cipher.decrypt(user[0].encode()).decode()
                if decrypted_password == password:
                    messagebox.showinfo("Success", f"Login successful! Welcome {name}")
                    self.current_user = name
                    self.show_user_dashboard()
                else:
                    messagebox.showerror("Error", "Incorrect password. Try again")
            else:
                messagebox.showerror("Error", "User does not exist. Please register first.")
        self.reset_entry(self.username_entry, self.password_entry)

    def show_user_dashboard(self):
        """
        Display the user dashboard with available options.

        Show buttons for managing passwords, including adding, modifying, and viewing stored credentials.
        """
        self.hide_all_widgets()
        tk.Label(self.root, font=self.custom_font, text=f"Welcome {self.current_user}").pack(pady=10)
        self.change_password_btn.pack(pady=10)
        self.add_password_btn.pack(pady=10)
        self.change_website_password_btn.pack(pady=10)
        self.change_website_username_btn.pack(pady=10)
        self.delete_password_btn.pack(pady=10)
        self.view_passwords_btn.pack(pady=10)
        self.back_btn.pack(pady=10)

    def show_change_password(self):
        """
        Display the form to change the user's password.

        Present an entry field for entering a new password, with a submit button.
        """
        self.hide_all_widgets()
        self.new_password_label.pack(pady=10)
        self.new_password_entry.pack(pady=10)
        self.toggle_visibility.pack(pady=10)
        self.change_password_submit.pack(pady=10)
        self.back_dashboard_btn.pack(pady=10)

    def change_password(self):
        """
        Update the user's password in the database.

        If the user does not provide a password, a strong password is generated and displayed.

        Store the password securely using encryption.
        """
        new_password = self.new_password_entry.get()
        show_pass = False
        if not new_password.strip():
            new_password = self.generate_strong_password()
            show_pass = True
        encrypted_password = self.cipher.encrypt(new_password.encode()).decode()
        self.cursor.execute("UPDATE users SET password = ? WHERE name = ?", (encrypted_password, self.current_user))
        self.conn.commit()
        messagebox.showinfo("Success", "Password updated successfully!")
        if show_pass:
            self.show_password(new_password)
        self.show_main_menu()
        self.reset_entry(self.new_password_entry)

    def show_add_password(self):
        """
        Display the form for adding a new password entry.

        Provide fields for website name, username, and password.
        """
        self.hide_all_widgets()
        self.website_name_label.pack(pady=10)
        self.website_name_entry.pack(pady=10)
        self.website_username_label.pack(pady=10)
        self.website_username_entry.pack(pady=10)
        self.website_password_label.pack(pady=10)
        self.website_password_entry.pack(pady=10)
        self.toggle_visibility.pack(pady=10)
        self.add_password_submit.pack(pady=10)
        self.back_dashboard_btn.pack(pady=10)

    def add_password(self):
        """
        Store a new password for a given website in the database.

        Encrypt the password before storing and ensures validation.
        """
        user_id = self.get_user_id(self.current_user)
        website = self.website_name_entry.get()
        username = self.website_username_entry.get()
        password = self.website_password_entry.get()
        if not website.strip() or not username.strip():
            messagebox.showerror("Error", "Missing information")
            return
        show_pass = False
        if not password.strip():
            password = self.generate_strong_password()
            show_pass = True
        encrypted_password = self.cipher.encrypt(password.encode()).decode()
        self.cursor.execute(
            "INSERT INTO passwords (user_id, website, username, password) VALUES (?, ?, ?, ?)",
            (user_id, website, username, encrypted_password)
        )
        self.conn.commit()
        messagebox.showinfo("Success", "Password added successfully!")
        if show_pass:
            self.show_password(password)
        self.show_user_dashboard()
        self.reset_entry(self.website_name_entry, self.website_username_entry, self.website_password_entry)

    def show_change_website_password(self):
        """
        Display the form for changing the password of a specific website/service.

        Provide fields for users to enter the website name and a new password, along with a submit button.
        """
        self.hide_all_widgets()
        self.website_name_label.pack(pady=10)
        self.website_name_entry.pack(pady=10)
        self.change_website_password_label.pack(pady=10)
        self.change_website_password_entry.pack(pady=10)
        self.toggle_visibility.pack(pady=10)
        self.change_website_password_submit.pack(pady=10)
        self.back_dashboard_btn.pack(pady=10)

    def change_website_password(self):
        """
        Update the password associated with a stored website/service in the database.

        If the website exists in the user's stored passwords, it replaces the old password with an encrypted new one.
        If no new password is provided, a strong password is generated automatically.
        """
        user_id = self.get_user_id(self.current_user)
        website = self.website_name_entry.get()
        new_password = self.change_website_password_entry.get()
        self.cursor.execute(
            "SELECT website FROM passwords WHERE user_id = ?",
            (user_id,)
        )
        websites = self.cursor.fetchall()
        website_exists = [website in [w[0] for w in websites]][0]
        if website_exists:
            show_pass = False
            if not new_password.strip():
                new_password = self.generate_strong_password()
                show_pass = True
            encrypted_password = self.cipher.encrypt(new_password.encode()).decode()
            self.cursor.execute(
                "UPDATE passwords set password = ? WHERE user_id = ? and website = ?",
                (encrypted_password, user_id, website)
            )
            self.conn.commit()
            messagebox.showinfo("Success", f"Password changed successfully for {website}!")
            if show_pass:
                self.show_password(new_password)
            self.show_user_dashboard()
        else:
            messagebox.showerror("Error", "No such website/service!")
        self.reset_entry(self.website_name_entry, self.change_website_password_entry)

    def show_change_website_username(self):
        """
        Display the form for changing the username associated with a website/service.

        Provide fields for users to enter the website name and a new username, along with a submit button.
        """
        self.hide_all_widgets()
        self.website_name_label.pack(pady=10)
        self.website_name_entry.pack(pady=10)
        self.change_website_username_label.pack(pady=10)
        self.change_website_username_entry.pack(pady=10)
        self.change_website_username_submit.pack(pady=10)
        self.back_dashboard_btn.pack(pady=10)

    def change_website_username(self):
        """
        Update the username associated with a stored website/service in the database.

        Validate if the website exists before applying the update.
        If no new username is provided, an error message is displayed.
        """
        user_id = self.get_user_id(self.current_user)
        website = self.website_name_entry.get()
        self.cursor.execute(
            "SELECT website FROM passwords WHERE user_id = ?",
            (user_id,)
        )
        websites = self.cursor.fetchall()
        website_exists = [website in [w[0] for w in websites]][0]
        if website_exists:
            new_username = self.change_website_username_entry.get()
            if not new_username.strip():
                messagebox.showerror("Error", "Username can not be empty!")
                return
            self.cursor.execute(
                "UPDATE passwords set username = ? WHERE user_id = ? and website = ?",
                (new_username, user_id, website)
            )
            self.conn.commit()
            messagebox.showinfo("Success", f"Username changed successfully for {website}")
            self.show_user_dashboard()
        else:
            messagebox.showerror("Error", "No such website/service!")
        self.reset_entry(self.website_name_entry, self.change_website_username_entry)

    def show_delete_password(self):
        """
        Display the form for deleting a stored password.

        Provide a field for users to enter the website/service name,
        along with a submit button to proceed.
        """
        self.hide_all_widgets()
        self.website_name_label.pack(pady=10)
        self.website_name_entry.pack(pady=10)
        self.delete_password_submit.pack(pady=10)
        self.back_dashboard_btn.pack(pady=10)

    def delete_password(self):
        """
        Delete a stored password from the database.

        Validate if the specified website exists before deletion.
        If found, the password is removed; otherwise, an error is displayed.
        """
        user_id = self.get_user_id(self.current_user)
        website = self.website_name_entry.get()
        self.cursor.execute(
            "SELECT website FROM passwords WHERE user_id = ?",
            (user_id,)
        )
        websites = self.cursor.fetchall()
        website_exists = [website in [w[0] for w in websites]][0]
        if website_exists:
            self.cursor.execute(
                "DELETE FROM passwords WHERE user_id = ? and website = ?",
                (user_id, website)
            )
            self.conn.commit()
            messagebox.showinfo("Success", f"Password deleted successfully")
            self.show_user_dashboard()
        else:
            messagebox.showerror("Error", "No such website/service!")
        self.reset_entry(self.website_name_entry)

    def show_view_passwords(self):
        """
        Display the button to view stored passwords.

        Users can click the button to view all passwords stored for their account.
        """
        self.hide_all_widgets()
        self.view_passwords_submit.pack(pady=(130, 0), anchor="n")
        self.back_dashboard_btn.pack(pady=10)

    def view_passwords(self):
        """
        Retrieve and displays all stored passwords for the current user.

        Show passwords in a scrollable pop-up window with readable formatting.
        """
        user_id = self.get_user_id(self.current_user)
        self.cursor.execute(
            "SELECT website, username, password FROM passwords WHERE user_id = ?", (user_id,))
        passwords = self.cursor.fetchall()
        if passwords:
            popup = tk.Toplevel()
            popup.title("Stored Passwords")
            popup.geometry("500x300")
            popup.update_idletasks()

            def adjust_position():
                popup_width = popup.winfo_width()
                popup_height = popup.winfo_height()
                screen_width = popup.winfo_screenwidth()
                screen_height = popup.winfo_screenheight()
                x_offset = (screen_width // 2) - (popup_width // 2)
                y_offset = (screen_height // 2) - (popup_height // 2)
                popup.geometry(f"{popup_width}x{popup_height}+{x_offset}+{y_offset}")

            popup.after(150, adjust_position)
            text_area = tk.Text(popup, wrap="word", font=self.custom_font)
            text_area.pack()
            text_content = "Please note that changes to this file does not have an impact on the real date stored in database.\n\n"
            text_content += "Your Passwords:\n\n"
            for password in passwords:
                decrypted_password = self.cipher.decrypt(password[2].encode()).decode()
                text_content += f"Website: {password[0]} | Username: {password[1]} | Password: {decrypted_password}\n\n"
            text_area.insert(index="1.0", chars=text_content)
            text_area.config(state="normal")
        else:
            tk.messagebox.showerror("Error", "You haven't added any passwords yet.")

    def run(self):
        """
        Start the Tkinter main event loop.

        Keep the password manager GUI running.
        """
        self.root.mainloop()
