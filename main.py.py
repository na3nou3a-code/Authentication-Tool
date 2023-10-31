import re
import getpass
import subprocess
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
import pyfiglet
import bcrypt

registered = False

def print_banner(text):
    banner = pyfiglet.Figlet(font='slant')
    print(banner.renderText(text))

def is_valid(email):
    """
    Validates an email address using a regular expression.
    
    Args:
        email (str): The email address to validate.
    
    Returns:
        str: The valid email address.
    """
    while True:
        email = input("Enter your email: ")
        regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
        if re.fullmatch(regex, email):
            print("Valid email")
            return email
        else:
            print("Invalid email. Please try again.")

def is_valid_password(password):
    """
    Validates a password to meet specific criteria.
    
    Args:
        password (str): The password to validate.
    
    Returns:
        str: The valid password.
    """
    while True:
        password = getpass.getpass("Enter the password: ")
        upp = any(c.isupper() for c in password)
        low = any(c.islower() for c in password)
        digit = any(c.isdigit() for c in password)
        spec = any(not c.isalnum() for c in password)
        
        if upp and low and digit and spec and len(password) >= 8:
            print("Password is valid.")
            return password
        else:
            print("Password is invalid. It should contain at least 1 uppercase letter, 1 lowercase letter, 1 digit, 1 special character, and be at least 8 characters long.")

def save_to_file(data):
    """
    Saves email and password data to a file.
    
    Args:
        data (str): The combined email and password data.
    """   
    with open("Enregistrement.txt", "a") as file:
        file.write(data + '\n')

def input_validate_and_save():
    """"
    Inputs, validates, and saves email and password data.
    """
    email = is_valid("Enter your email: ")
    password = is_valid_password("Enter the password: ")

    creds = f"Email: {email} Password: {password}"
    save_to_file(creds)

def authenticate():
    email = input("Enter your email: ")
    password = getpass.getpass("Enter your password: ")

    if is_registered(email):
        with open("Enregistrement.txt", "r") as file:
            for line in file:
                if f"Email: {email}" in line:
                    stored_password = re.search(r"Password: (.+)", line)
                    if stored_password:
                        stored_password = stored_password.group(1)
                        break

        if stored_password == password:
            print("Authentication successful!")
            return email, True
        else:
            print("Authentication failed. Please try again.")
    else:
        print("Authentication failed. Please try again or register.")
    return email, False

def is_registered(email):
    try:
        with open("Enregistrement.txt", "r") as file:
            for line in file:
                if f"Email: {email}" in line:
                    return True
    except FileNotFoundError:
        return False

# Function to hash a word using SHA-256
def hash_sha256(word):
    hash = hashlib.sha256(word.encode()).hexdigest()
    return hash

# Function to hash a word with a salt using bcrypt
def hash_salt(word):
    salt = bcrypt.gensalt()
    hashed_word = bcrypt.hashpw(word.encode(), salt)
    return hashed_word
filename = "wordlist.txt"
def load_dictionary(filename):
    dictionary = {}
    with open(filename, 'r') as file:
        for line in file:
            word, hash = line.strip().split(':')
            dictionary[word] = hash
    return dictionary

# Function to generate RSA key pairs and save them to files
def openssl():
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-out", "private_key.pem"])
    subprocess.run(["openssl", "rsa", "-pubout", "-in", "private_key.pem", "-out", "public_key.pem"])

# Function to encrypt a message using RSA
def encrypt_rsa(public_key_file, message):
    with open(public_key_file, "rb") as f:
        rpk = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(rpk)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

# Function to decrypt an RSA-encrypted message
def decrypt_rsa(private_key_file, encrypted_message):
    with open(private_key_file, "rb") as f:
        private_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(private_key)
    try :
        decrypted_message = cipher.decrypt(encrypted_message)
        return decrypted_message.decode()
    except ValueError as e :
        print("Decryption error", e )
        return None

# Function to sign a message using OpenSSL
def sign_message_with_openssl(private_key_file, message):
    try:
        command = ["openssl", "dgst", "-sign", private_key_file, "-sha256"]
        signature = subprocess.check_output(command, input=message.encode())
        return signature
    except subprocess.CalledProcessError:
        return None

# Function to verify a message's signature using OpenSSL
def verify_message_with_openssl(public_key_file, message, signature):
    with open("message.txt", "w") as message_file:
        message_file.write(message)
    with open("signature.bin", "wb") as signature_file:
        signature_file.write(signature)
    command = ["openssl", "dgst", "-verify", public_key_file, "-sha256", "-signature", "signature.bin", "message.txt"]
    result = subprocess.check_output(command)
    return "Verified" in result.decode()


def generate_self_signed_certificate(cert_file, key_file, common_name, days=365):
    try:
        # Generate a private key
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-out", key_file])

        # Generate a self-signed certificate
        subprocess.run([
            "openssl", "req", "-x509", "-new", "-key", key_file,
            "-out", cert_file, "-days", str(days),
            "-subj", f"/CN={common_name}"
        ])

        return True
    except subprocess.CalledProcessError:
        return False

def encrypt_message_with_certificate(cert_file, message):
    # Load the public key from the certificate
    with open(cert_file, "rb") as f:
        certificate = f.read()
        key = RSA.import_key(certificate)
        cipher = PKCS1_OAEP.new(key)
        encrypted_message = cipher.encrypt(message.encode())
        return encrypted_message

def main_menu():
    authenticated = False

    while not authenticated:
        print_banner("Authentication Tool")
        print("Menu:")
        print("1- Authenticate")
        print("2- Register")
        print("3- Logout")

        choice = input("Enter your choice (1, 2, or 3): ")

        if choice == "1":
            email, auth_success = authenticate()

            if auth_success:
                print("Authentication successful!")
                authenticated = True
            else:
                print("Authentication failed. Please try again or register.")
        elif choice == "2":
            input_validate_and_save()
        elif choice == "3":
            return

    while authenticated:
            print_banner("Authentication Tool")
            print("Menu:")
            print("A- Donnez un mot à haché (en mode invisible)")
            print("   a- Haché le mot par sha256")
            print("   b- Haché le mot en générant un salt (bcrypt)")
            print("   c- Attaquer par dictionnaire le mot inséré")
            print("   d- Revenir au menu principal")
            print("B- Chiffrement (RSA)")
            print("   a- Générer les paires de clés dans un fichier")
            print("   b- Chiffrer un message de votre choix par RSA")
            print("   c- Déchiffrer le message (b)")
            print("   d- Signer un message de votre choix par RSA")
            print("   e- Vérifier la signature du message (d)")
            print("   f- Revenir au menu principal")
            print("C- Certificat (RSA)")
            print("   a- Générer les paires de clés dans un fichier")
            print("   b- Générer un certificat autosigné par RSA")
            print("   c- Chiffrer un message de votre choix par ce certificat")
            print("   d- Revenir au menu principal")

            choice = input("Enter your choice: ")
            if choice == "A":
                while True:
                    sub_choice = input("Enter a sub-choice (a, b, c, or d): ")
                    if sub_choice == "a":
                        text = input("Enter the text to hash: ")
                        hashed_text = hash_sha256(text)
                        print("SHA-256 Hash:", hashed_text)
                    elif sub_choice == "b":
                        text = input("Enter the text to hash: ")
                        hashed_text = hash_salt(text)
                        print("BCrypt Hash:", hashed_text)
                    elif sub_choice == "c":
                        hash= input("Enter the hashed text to attack: ")
                        dictionary = load_dictionary(filename)
                        word = dictionary.get(hash)
                        if word:
                            print(f"Attacked word: {word}")
                        else:
                            print("No match found in the dictionary.")
                    elif sub_choice == "d":
                        break
                    else:
                        print("Invalid sub-choice. Please try again.")

            elif choice == "B":
                while True:
                    sub_choice = input("Enter a sub-choice (a, b, c, d, e, or f): ")
                    if sub_choice == "a":
                        openssl()
                        print("RSA key pairs generated and saved to 'public_key.pem' and 'private_key.pem'.")
                    elif sub_choice == "b":
                        public_key_file = input("Enter the path to the recipient's public key file: ")
                        message = input("Enter the message to encrypt: ")
                        encrypted_message = encrypt_rsa(public_key_file, message)
                        print("Encrypted Message:", encrypted_message.hex())
                    elif sub_choice == "c":
                        private_key_file = input("Enter the path to your private key file: ")
                        encrypted_message_hex = input("Enter the encrypted message in hexadecimal format: ")
                        encrypted_message= bytes.fromhex(encrypted_message_hex)
                        decrypted_message = decrypt_rsa(private_key_file, encrypted_message)
                        print("Decrypted Message:", decrypted_message)
                    elif sub_choice == "d":
                        message = input("Enter the message to sign: ")
                        private_key_file = input("Enter the path to your private key file: ")
                        signature = sign_message_with_openssl(private_key_file, message)
                        if signature:
                            print("Message Signature:", signature.hex())
                        else:
                            print("Message signing failed.")
                    elif sub_choice == "e":
                        message = input("Enter the message: ")
                        signature_hex = input("Enter the signature in hexadecimal format: ")
                        signature = bytes.fromhex(signature_hex)
                        public_key_file = input("Enter the path to the public key file: ")
                        if verify_message_with_openssl(public_key_file, message, signature):
                            print("Signature is valid.")
                        else:
                            print("Signature is invalid.")
                    elif sub_choice == "f":
                        break
                    else:
                        print("Invalid sub-choice. Please try again.")

            elif choice == "C":
                while True:
                    sub_choice = input("Enter a sub-choice (a, b, c, or d): ")
                    if sub_choice == "a":
                        openssl()
                        print("RSA key pairs generated and saved to 'public_key.pem' and 'private_key.pem'.")
                    elif sub_choice == "b":
                        cert_file = "self_signed_certificate.pem"
                        key_file = "self_signed_key.pem"
                        common_name = "nour"
                        if generate_self_signed_certificate(cert_file, key_file, common_name):
                            print("Self-signed certificate generated successfully.")
                        else:
                            print("Failed to generate a self-signed certificate.")
                    elif sub_choice == "c":
                        message = "This is a secret message"
                        cert_file = "self_signed_certificate.pem"
                        encrypted_message = encrypt_message_with_certificate (cert_file , message )
                        print ("Encrypted message:", encrypted_message)
                    elif sub_choice == "d":
                        break
                    else:
                        print("Invalid sub-choice. Please try again.")
            else:
                print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()
