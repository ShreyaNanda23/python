from cryptography.fernet import Fernet
import os
from getpass import getpass

KEY_FILE = "key.key"
PASSWORD_FILE = "passwords.txt"

# Generate key if not already present
def write_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

# Load the encryption key from file
def load_key():
    if not os.path.exists(KEY_FILE):
        print("[INFO] Encryption key not found. Generating a new one...")
        write_key()
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

# Set up Fernet with loaded key
key = load_key()
fer = Fernet(key)

# View stored account-passwords
def view():
    if not os.path.exists(PASSWORD_FILE):
        print("[INFO] No passwords saved yet.")
        return

    with open(PASSWORD_FILE, 'r') as f:
        for line in f:
            data = line.strip()
            if "|" not in data:
                continue
            user, encrypted = data.split("|")
            try:
                decrypted_pwd = fer.decrypt(encrypted.encode()).decode()
                print(f"User: {user} | Password: {decrypted_pwd}")
            except Exception as e:
                print(f"[ERROR] Failed to decrypt password for {user}.")

# Add a new account-password pair
def add():
    name = input('Account Name: ')
    pwd = getpass("Password (hidden input): ")
    encrypted_pwd = fer.encrypt(pwd.encode()).decode()

    with open(PASSWORD_FILE, 'a') as f:
        f.write(name + "|" + encrypted_pwd + "\n")
    print("[INFO] Password saved successfully.")

# Main loop
def main():
    print("🔐 Welcome to the Simple Password Manager")

    while True:
        mode = input("\nChoose an option: [view | add | quit]: ").lower()
        if mode == "quit" or mode == "q":
            print("Goodbye!")
            break
        elif mode == "view":
            view()
        elif mode == "add":
            add()
        else:
            print("[ERROR] Invalid option. Try again.")

if __name__ == "__main__":
    main()
