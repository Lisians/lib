import base64
import os
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

file_path = 'secrets/variables.json'
PASSWORD = os.getenv("LIB_PASSWORD")
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b'salt',
    iterations=390000,
)
key = base64.urlsafe_b64encode(kdf.derive(bytes(PASSWORD, 'utf-8')))
fernet = Fernet(key)

with open(file_path, encoding='UTF8') as f:
    original = f.read()
    # variables = json.load(f)

# encrypting the file
encrypted = fernet.encrypt(bytes(original, 'utf-8'))

# opening the file in write mode and
# writing the encrypted data
with open(file_path + '_enc', 'wb') as encrypted_file:
    encrypted_file.write(encrypted)

# opening the encrypted file
with open(file_path + '_enc', 'rb') as enc_file:
    encrypted = enc_file.read()

# decrypting the file
decrypted = fernet.decrypt(encrypted).decode('utf8')
print(decrypted)
