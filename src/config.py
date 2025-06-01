import os
import sqlite3

from cryptography.fernet import Fernet


def create_cipher():
    # Ensure the key is generated only one time
    os.makedirs("key", exist_ok=True)
    if not os.path.exists("key/encryption_key.key"):
        encryption_key = Fernet.generate_key()
        with open("key/encryption_key.key", "wb") as f:
            f.write(encryption_key)
    with open("key/encryption_key.key", "rb") as f:
        encryption_key = f.read()
    cipher = Fernet(encryption_key)
    return cipher


def create_database():
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
