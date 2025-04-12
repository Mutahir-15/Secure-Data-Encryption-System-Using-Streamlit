# Secure Data Encryption System using Streamlit
import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

#Initializing Session state
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "current_page" not in st.session_state:
    st.session_state.current_page = "Register"

# Generating a Fernet key
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
cipher = Fernet(st.session_state.fernet_key)

# Files for Storage
DATA_FILE = "data.json"
USERS_FILE = "users.json"

# Loading data from JSON files
def load_data(file_path, default_value):
    try:
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                return json.load(f)
    except json.JSONDecodeError:
        pass
    return default_value

def save_data(file_path, data):
    with open(file_path, "w") as f:
        json.dump(data, f)

# Loading stored data and users
stored_data = load_data(DATA_FILE, {})
users = load_data(USERS_FILE, {})

# Function to hash passwords/passkeys using SHA-256
def hash_value(value):
    return hashlib.sha256(value.encode()).hexdigest()

# Function for Data Encyption
def encrypt_data(text, passkey):
    try:
        encrypted_text = cipher.encrypt(text.encode()).decode()
        return encrypted_text
    except Exception as e:
        return f"Error during encryption: {str(e)}"
    
# Function to Decrypt Data
def decrypt_data(encrypted_text, passkey):
    try:
        hashed_passkey = hash_value(passkey)
        if encrypted_text in stored_data and stored_data[encrypted_text]["passkey"] == hashed_passkey:
            decrypted_text = cipher.decrypt(encrypted_text.encode()).decode()
            return decrypted_text
        return "Incorrect passkey or encrypted data not found."
    except Exception as e:
        return f"Error during decryption: {str(e)}"
    
# UI Section
st.set_page_config(page_title="Secure Data Encryption System", page_icon=":lock:")
st.title("Secure Data Encryption System")

# Navigation tabs
if st.session_state.logged_in:
    menu = ["Home", "Store Data", "Retrieve Data", "Logout"]
else:
    menu = ["Login", "Register"]

# Redirecting user to the login page if not logged in
if not st.session_state.logged_in and st.session_state.current_page not in ["Login", "Register"]:
    st.session_state.current_page = "Login"

choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.current_page))
st.session_state.current_page = choice

#  Registration page
if choice == "Register":
    st.subheader("Register")
    new_username = st.text_input("Username")
    new_password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    if st.button("Register"):
        if new_password == confirm_password:
            if new_username not in users:
                users[new_username] = hash_value(new_password)
                save_data(USERS_FILE, users)
                st.success("Registration successful. Please login.")
            else:
                st.error("Username already exists. Please choose a different username.")
        else:
            st.error("Passwords do not match. Please try again.")

# Login page
elif choice == "Login":
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username in users and users[username] == hash_value(password):
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.failed_attempts = 0
            st.session_state.current_page = "Home"
            st.success(f"Welcome, {username}!")
        else:
            st.session_state.failed_attempts += 1
            if st.session_state.failed_attempts >= 3:
                st.error("Too many failed attempts. Please try again later.")
            else:
                st.error("Invalid username or password. Please try again.")

# Home poge (only accessible when logged in)
elif choice == "Home":
    st.subheader(f"🏠 Welcome, {st.session_state.username}!")
    st.write("""
    Use this app to **securely store and retrieve data** using unique passkeys.  
    - Navigate to **Store Data** to encrypt and save your data.  
    - Navigate to **Retrieve Data** to decrypt and view your data.  
    - After 3 failed decryption attempts, you’ll need to re-login.
    """)

# Stored Data page
elif choice == "Store Data":
    st.subheader("Store Data Securely")
    user_data = st.text_area("Enter Data:", placeholder="Type the data you want to encrypt...")
    passkey = st.text_input("Enter Passkey:", type="password", placeholder="Create a passkey for this data...")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            with st.spinner("Encrypting and saving data..."):
                hashed_passkey = hash_value(passkey)
                encrypted_text = encrypt_data(user_data, passkey)
                if "Error" in encrypted_text:
                    st.error(encrypted_text)
                else:
                    stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
                    save_data(DATA_FILE, stored_data)
                    st.success("Data stored securely!")
                    st.write("**Encrypted Data (copy this to retrieve later):**")
                    st.code(encrypted_text)
        else:
            st.error("Both fields are required!")

# Retrieve Data page
elif choice == "Retrieve Data":
    st.subheader("Retrieve Data")
    encrypted_text = st.text_input("Enter Encrypted Data:", placeholder="Paste the encrypted data here...")
    passkey = st.text_input("Enter Passkey:", type="password", placeholder="Enter the passkey for this data...")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            with st.spinner("Decrypting data..."):
                decrypted_text = decrypt_data(encrypted_text, passkey)
                if decrypted_text:
                    st.success("Data decrypted successfully!")
                    st.write("**Decrypted Data:**")
                    st.code(decrypted_text)
                else:
                    st.error("Incorrect passkey or encrypted data not found.")
        else:
            st.error("Both fields are required!")

# Logout page
elif choice == "Logout":
    st.subheader("Logout")
    st.write("Are you sure you want to log out?")
    if st.button("Confirm Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.session_state.failed_attempts = 0
        st.session_state.current_page = "Login"
        st.success("Logged out successfully!")
        st.rerun()