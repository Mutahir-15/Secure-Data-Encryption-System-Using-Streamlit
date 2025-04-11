# Secure Data Encryption System Using Streamlit

## Overview
This project is a Streamlit web application that allows users to register, log in, and securely store/retrieve data using Fernet encryption. It was developed as a class project for GIAIC on April 08, 2025.

## Features
- User registration and login with username/password authentication (password strength enforced).
- Securely stores data using Fernet encryption with a user-provided passkey.
- Retrieves data by decrypting with the correct passkey.
- Limits users to 3 failed decryption attempts before requiring re-login.
- Persists data and user credentials in JSON files (`data.json` and `users.json`).
- Includes logout functionality and logging for debugging.
- User-friendly interface with loading spinners, input validation, and custom styling.

## How to Use
1. Open the app at [insert Streamlit Cloud URL here].
2. **Register**: Create a username and password (at least 8 characters, 1 uppercase, 1 number).
3. **Login**: Log in with your credentials to access the system.
4. Navigate using the sidebar:
   - **Store Data**: Enter text and a passkey to encrypt and save your data.
   - **Retrieve Data**: Enter the encrypted data and passkey to decrypt and view your data.
   - **Logout**: Log out to end your session.
5. After 3 failed decryption attempts, you’ll be logged out and must log in again.

## Security Features
- Uses Fernet (symmetric encryption) from the `cryptography` library.
- Hashes passkeys and passwords using SHA-256.
- Enforces password strength during registration.
- Limits failed attempts (both login and decryption) to 3 before requiring re-login.
- Stores data in-memory and persists it to JSON files (excluded from Git).
- Logs user actions and errors to `app.log`.

## Limitations
- Single-user system; all data is stored in a shared dictionary (multi-user support could be added).
- Fernet key is stored in session state; in production, it should be stored securely (e.g., in an environment variable).
- No time-based lockout for failed attempts (could be added for production).

## Setup for Local Development
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/your-repo.git
   cd Secure-data-encryption-system
   
2. Install dependencies:
   ```bash
   pip install -r requirements.txt

   
3. Run the app:
   ```bash
   streamlit run app.py
