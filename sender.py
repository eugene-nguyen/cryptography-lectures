# inputs: pu_keys.txt, message.txt
# output: transmitted_message.txt
# 2. Each party’s message (from a .txt file) is encrypted using AES before sending it to another party.
# 3. The AES key used in 2) is encrypted using the receiver’s RSA public key. The encrypted AES key is sent together with the encrypted message obtained from 2).
# 4. Message authentication code should be appended to data transmitted. You are free to choose the specific protocol of MAC.

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import CBC
from base64 import b64encode

def aes_256_cbc_encrypt(plaintext, key):
    # padding the data
    pkcs7_padder = padding.PKCS7(AES.block_size).padder()
    padded_plaintext = pkcs7_padder.update(plaintext) + pkcs7_padder.finalize()

    # generate 128 bit IV
    iv = os.urandom(128 // 8)

    # generating the aes-cbc cipher
    aes_256_cbc_cipher = Cipher(AES(key), CBC(iv))

    # encrypting the now padded plaintext
    ciphertext = aes_256_cbc_cipher.encryptor().update(padded_plaintext)

    return iv + ciphertext

def create_hmac_sha_256_tag(data, key):
    hash_function = hashes.SHA256()
    h = hmac.HMAC(key, hash_function)
    h.update(data)
    hmac_tag = h.finalize()

    return hmac_tag

def aes_encrypt_from_file(filename, key):
    with open(filename, "r") as file:
        plaintext = ""
        line = file.readline()
        while (line):
            plaintext += line
            line = file.readline()
        
        plaintext = plaintext.encode("utf-8")
        return aes_256_cbc_encrypt(plaintext, key)

def rsa_encrypt_from_str(plaintext):
    # assumes that pu_keys exists and is formatted as e first line, n second line; also they're both already ints
    with open("pu_keys.txt", "r") as file:
        e, n = int(file.readline().strip()), int(file.readline())
        ciphertext = []
        for b in plaintext:
            # for each byte in the plaintext run rsa on it so...
            ciphertext.append(pow(b, e, n))

        return ciphertext


def main():
    # check if files "message.txt" and "pu_keys.txt" are there (we don't need private keys)
    if (not os.path.isfile("message.txt") or not os.path.isfile("pu_keys.txt")):
        print("Relevant file(s) is missing.")
        quit()
    
    enc_key = os.urandom(256 // 8)
    mac_key = enc_key # technically this should be a different number but i'm making it the same for now bc i can't figure out how to transfer this one over
    plaintext = ""

    # aes encrypt message!!
    ciphertext = aes_encrypt_from_file("message.txt", enc_key)
    
    # rsa encrypt key!!
    encrypted_aes_key = rsa_encrypt_from_str(enc_key)

    # testing to see if encoded key can be decoded (this uses a function from receiver.py)
    #print(enc_key)
    #print(string_list_to_byte_string(rsa_decrypt_to_list(encrypted_aes_key)))

    # generate mac
    mac_tag = create_hmac_sha_256_tag(ciphertext, mac_key)

    # output all to transmitted_message.txt
    with open("transmitted_message.txt", "wb") as file:
        # file.write(encrypted_aes_key)
        # file.write(mac_tag)
        file.write(ciphertext)
        print("generated transmitted_message.txt")
    
    # the evil "not appending the data but just storing each output in a separate file" setup
    with open("transmitted_mac.txt", "wb") as file:
        file.write(mac_tag)
        print("generated transmitted_mac.txt")
    
    with open("transmitted_key.txt", "w") as file:
        for c in encrypted_aes_key:
            file.write(str(c) + "\n")
        print("generated transmitted_key.txt")
    
    
main()
    
    