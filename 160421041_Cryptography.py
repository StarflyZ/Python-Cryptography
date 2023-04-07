from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES 
import os
from Cryptodome.Random import get_random_bytes

"""Enkripsi Method"""

def encrypt(plain_text, password):
    # generate a random salt
    salt = get_random_bytes(AES.block_size)

    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    return{
        'cipher_text' : b64encode(cipher_text).decode('utf-8'),
        'salt' : b64encode(salt).decode('utf-8'),
        'nonce' : b64encode(cipher_config.nonce).decode('utf-8'),
        'tag' : b64encode(tag).decode('utf-8')
    }

def decrypt(enc_dict, password):
    #decode the dictionary entries from base64
    salt = b64decode(enc_dict['salt'])
    cipher_text = b64decode(enc_dict['ciper_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])

    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    decrypt = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypt

#Main Method

def main():
    password = "uby"
    
    encrypt = encrypt("Universitas Surabaya", password)
    print(encrypt)

    decrypt = decrypt(encrypted, password)
    print(bytes.decode(decrypt))
    
main()