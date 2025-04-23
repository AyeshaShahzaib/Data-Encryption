import streamlit as st
import pandas as pd
import hashlib
import os
from encryption.aes_encryption import encrypt_data, decrypt_data

# Load user data
@st.cache_data
def load_data():
    if not os.path.exists("data"):
        os.makedirs("data")
    try:
        return pd.read_csv("data/user_data.csv")
    except FileNotFoundError:
        return pd.DataFrame(columns=["Username", "Password", "Encrypted_Data"])

# Save user data
def save_data(df):
    df.to_csv("data/user_data.csv", index=False)

# Register user
def register_user():
    df = load_data()
    username = st.text_input("Enter a Username")
    password = st.text_input("Enter a Password", type="password")

if st.button("Register"):
    if username and password:
        if username in df["Username"].values:
            st.warning("Username already exists. Please choose a different one.")
            st.stop()  # This stops further execution
        else:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            new_user = pd.DataFrame([{"Username": username, "Password": hashed_password, "Encrypted_Data": ""}])
            df = pd.concat([df, new_user], ignore_index=True)
            save_data(df)
            st.success("Account created successfully! Please log in.")
            st.experimental_rerun()

# Login user
def login_user():
    df = load_data()
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        user_data = df[df["Username"] == username]
        if not user_data.empty and user_data["Password"].values[0] == hashed_password:
            st.session_state.username = username
            st.session_state.logged_in = True
            st.success("Login successful!")
            st.info("Please click below to continue.")
            if st.button("Continue"):
                st.session_state.view = "main"

        else:
            st.error("Invalid credentials")

# Encrypt and decrypt data
def encrypt_decrypt_data():
    st.subheader(f"Welcome, {st.session_state.username}")
    option = st.selectbox("Choose an option", ["Encrypt Data", "Decrypt Data"])

    if option == "Encrypt Data":
        data_to_encrypt = st.text_area("Enter the data you want to encrypt")
        password = st.text_input("Enter a Password for Encryption", type="password")

        if st.button("Encrypt"):
            encrypted = encrypt_data(data_to_encrypt, password)
            st.session_state.encrypted_data = encrypted
            st.success("Data encrypted successfully!")
            st.code(encrypted)

    elif option == "Decrypt Data":
        password = st.text_input("Enter the Password for Decryption", type="password")
        if st.button("Decrypt"):
            if "encrypted_data" in st.session_state:
                try:
                    decrypted = decrypt_data(st.session_state.encrypted_data, password)
                    st.success("Data decrypted successfully!")
                    st.code(decrypted)
                except:
                    st.error("Decryption failed. Wrong password or invalid data.")
            else:
                st.error("No encrypted data found.")

# Main view
def home():
    st.title("🔐 Personal Data Encryption")

    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        option = st.selectbox("Select an option", ["Login", "Register"])
        if option == "Register":
            register_user()
        else:
            login_user()
    else:
        encrypt_decrypt_data()

if __name__ == "__main__":
    home()
