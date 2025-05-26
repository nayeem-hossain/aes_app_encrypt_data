from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet, InvalidToken
from flask import current_app
import base64
import os

def encrypt_key(raw_key: str) -> str:
    """Encrypt AES key with master key"""
    fernet = Fernet(current_app.config['MASTER_KEY'])
    return fernet.encrypt(raw_key.encode()).decode()

def decrypt_key(encrypted_key: str) -> str:
    """Decrypt AES key with master key"""
    try:
        fernet = Fernet(current_app.config['MASTER_KEY'])
        return fernet.decrypt(encrypted_key.encode()).decode()
    except InvalidToken:
        current_app.logger.error("Key decryption failed - possible tampering!")
        raise

class AESCipher:
    def __init__(self, key=None):
        if key is None:
            key = get_random_bytes(32)  # AES-256
        self.key = key
    
    def encrypt(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data, AES.block_size))
        return base64.b64encode(iv + encrypted).decode('utf-8')
    
    def encrypt_file(self, file_path, output_path):
        """Encrypt file and save to output path"""
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        with open(file_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            f_out.write(iv)
            while True:
                chunk = f_in.read(64 * 1024)  # 64KB chunks
                if len(chunk) == 0:
                    break
                elif len(chunk) % AES.block_size != 0:
                    chunk = pad(chunk, AES.block_size)
                f_out.write(cipher.encrypt(chunk))
    
    def decrypt(self, encrypted_data):
        encrypted_data = base64.b64decode(encrypted_data)
        iv = encrypted_data[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
        return decrypted.decode('utf-8')
    
    def decrypt_file(self, file_path, output_path):
        """Decrypt file and save to output path"""
        with open(file_path, 'rb') as f_in:
            iv = f_in.read(AES.block_size)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            
            with open(output_path, 'wb') as f_out:
                while True:
                    chunk = f_in.read(64 * 1024)  # 64KB chunks
                    if len(chunk) == 0:
                        break
                    f_out.write(unpad(cipher.decrypt(chunk), AES.block_size))
    
    def get_key(self):
        return base64.b64encode(self.key).decode('utf-8')
    
    @staticmethod
    def key_from_string(key_str):
        return base64.b64decode(key_str.encode('utf-8'))