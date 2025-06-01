import os
import sqlite3
from typing import Tuple

from cryptography.fernet import Fernet


def create_cipher() -> Fernet:
    """
    Generate or retrieve an encryption cipher for securing stored passwords.

    This function ensures an encryption key is generated only once and stored securely.
    If the key already exists, it is loaded instead of generating a new one.

    :return: A `Fernet` cipher instance for encrypting and decrypting passwords.
    """
    os.makedirs("key", exist_ok=True)
    if not os.path.exists("key/encryption_key.key"):
        encryption_key = Fernet.generate_key()
        with open("key/encryption_key.key", "wb") as f:
            f.write(encryption_key)
    with open("key/encryption_key.key", "rb") as f:
        encryption_key = f.read()
    cipher = Fernet(encryption_key)
    return cipher


def create_database() -> Tuple[sqlite3.Cursor, sqlite3.Connection]:
    """
    Create or connect to the password manager's database.

    Ensure required tables (`users` and `passwords`) are created if they do not already exist.
    The `users` table stores user credentials, while the `passwords` table tracks passwords
    associated with specific websites/services for each user.

    :return: A tuple `(cursor, conn)` representing the database cursor and connection.
    """
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/password_manager.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(50) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            website VARCHAR(50) NOT NULL,
            username VARCHAR(50) NOT NULL,
            password VARCHAR(50) NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        );
    """)
    conn.commit()
    return cursor, conn
