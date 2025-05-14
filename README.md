# PasswordManager
A simple password manager in Python that uses encryption to securely store, generate, and retrieve passwords.

## Features
Master Password: Secure access with a master password. (1234) -> you must change it

Encryption: Passwords are stored securely using Fernet encryption.

Password Generation: Generate random strong passwords.

Password Strength: Shows password strength (Weak, Medium, Strong).

Retrieve Passwords: Easily retrieve saved passwords.

## Requirements
Python 3.x

### Libraries:

tkinter (usually pre-installed)

cryptography (pip install cryptography)

pyperclip (pip install pyperclip)

## Notes
If the key or data file is corrupted or lost, it will not be possible to recover the passwords.
The master password is essential for accessing the program. If forgotten, there is no way to recover it.
