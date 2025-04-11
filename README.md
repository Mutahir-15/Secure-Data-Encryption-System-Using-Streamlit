# 🔐 Secure Data Encryption System - Streamlit App

A **Streamlit-based Python application** for secure data storage and retrieval using **passkey encryption**. This lightweight app ensures user privacy by encrypting and decrypting data in memory, **without the need for external databases**.

## 🚀 Features

- 🔒 **In-Memory Encryption/Decryption**: Store and retrieve sensitive data securely.
- 🔑 **Passkey-Based Access**: User-provided passkey for encryption and decryption.
- 🔁 **Reauthorization System**: Re-prompts for authentication after multiple failed decryption attempts.
- 💾 **No Database Required**: All operations are handled in RAM for maximum security.
- 📱 **User-Friendly UI**: Built with Streamlit for easy interaction.

## 🛠 Technologies Used
- Python
- Streamlit
- Cryptography / hashlib (or equivalent Python encryption libraries)

## 🧪 Installation

```bash
# Clone the repository
git clone https://github.com/your-username/secure-data-vault.git
cd secure-data-vault

# (Optional) Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## ▶️ Run the App
```bash
streamlit run app.py
```

## 🔐 How It Works
1. Enter your **data** and **encryption passkey**.
2. The app encrypts the data and stores it in memory.
3. Use the same passkey to decrypt it later.
4. Multiple failed attempts trigger reauthorization, preventing brute-force attacks.

## 📄 License
This project is open-source under the [MIT License](LICENSE).

---
🛡️ Built for privacy-first applications. No cloud. No database. Just encryption magic!
