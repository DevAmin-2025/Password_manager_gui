# Password_manager
A secure password management application built using Python, Tkinter, SQLite, and Fernet encryption. This project enables users to store, manage, and securely encrypt their passwords while providing an intuitive graphical interface.

## Features
- **User Registration** & Login Secure user authentication system using encrypted passwords.
- **Password Encryption** All passwords are encrypted using Fernet before storage.
- **Password Management** Users can add, update, delete, and view saved passwords.
- **Strong Password Generation** Automatically generates secure passwords when needed.
- **Intuitive GUI** Built using `Tkinter`, providing a seamless user experience.
- **Database Security** Uses `SQLite` with foreign key constraints for structured data storage.

## Project Structure
```
PASSWORD_MANAGER
├── data
│   └── password_manager.db  # Stores encrypted user and password data (will be created after the first run)
├── key
│   └── encryption_key.key   # Encryption key used for password protection (will be created after the first run)
├── src
│   ├── config.py            # Handles database and encryption setup
│   ├── main.py              # Entry point for running the application
│   ├── password_manager.py  # Manages the Tkinter GUI and user interactions
├── .gitignore               # Ignore sensitive files from version control
├── LICENSE                  # Project license
├── README.md                # Project documentation
└── requirements.txt         # Dependencies required to run the project
```

## Installation
1. **Clone the Repository**: Open your terminal and run the following command to clone the repository:
```bash
git clone https://github.com/your-username/your-repo.git
```
Replace your-username and your-repo with the actual GitHub username and repository name.
2. Navigate to the project directory and add it to `PYTHONPATH`:
```bash
export PYTHONPATH=$(pwd)
```
3. Install dependecies:
```bash
pip install -r requirements.txt
```
4. Run the application:
```bash
python src/main.py
```

## Usage
1. Register a new user with a username and password. If no password is provided, a strong password will be generated.
2. Log in using registered credentials.
3. Manage passwords:
    - Add passwords for websites/services.
    - Change stored passwords and usernames.
    - View and delete saved passwords.
4. Secure storage:
    - All passwords are encrypted before storage using `Fernet`.

## License
This project is licensed under the MIT License.
