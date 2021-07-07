import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC



def getKey (salt, password):
    print(password)
    print(salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(salt.encode()),
        iterations=100000
    )
    key = base64.urlsafe_b64encode(kdf.derive(bytes(password.encode())))
    f = Fernet(key)
    return f

def encryptMessage(key, message):
    token = key.encrypt(bytes(message.encode()))
    return(token)

def decrypt(key, token):
    try:
        str = key.decrypt(token)
    except:
        print("Invalid Token")
        str = ""
        
    return(str)
    

#message = b"hello world"
#message = "hello world"
#password = b"password"
#salt = os.urandom(16)
#salt = b"hello"
#kdf = PBKDF2HMAC(
#    algorithm=hashes.SHA256(),
#    length=32,
#    salt=salt,
#    iterations=100000
#    )
#key = base64.urlsafe_b64encode(kdf.derive(password))
#f = Fernet(key)
#token = f.encrypt(bytes(message.encode()))
#token = f.encrypt(message)
#print(token)
#b'...'
#print(f.decrypt(token))
#b'Secret Message!'
