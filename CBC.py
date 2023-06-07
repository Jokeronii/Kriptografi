#!/usr/bin/env python
# coding: utf-8

#imports
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
import binascii

#inputs
plaintext="12809"
key = pad(b"UDINUS",AES.block_size)
iv=pad(b"0101",AES.block_size)

#Encryption
def _encrypt(plaintext):
    data_bytes=bytes(plaintext,'utf-8')
    padded_bytes=pad(data_bytes, AES.block_size)
    AES_obj=AES.new(key, AES.MODE_CBC,iv)
    ciphertext=AES_obj.encrypt(padded_bytes)
    return ciphertext
ciphertext=_encrypt(plaintext)
print(ciphertext)
print(binascii.hexlify(ciphertext))

#Decryption
def _decrypt (ciphertext):
    AES_obj=AES.new(key, AES.MODE_CBC,iv)
    raw_bytes=AES_obj.decrypt(ciphertext)
    extraced_bytes=unpad(raw_bytes,AES.block_size)
    return extraced_bytes
plaintext=_decrypt(ciphertext)
print (plaintext)
print (plaintext.decode('ascii'))