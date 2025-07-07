# 5. The receiver should be able to successfully authenticate, decrypt the message, and read the original message.

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import CBC

def verify_hmac_sha_256_tag(mac_tag, received_ciphertext, key):
    hash_function = hashes.SHA256()
    h = hmac.HMAC(key, hash_function)
    h.update(received_ciphertext)
    h.verify(mac_tag)

def aes_256_cbc_decrypt(received_ciphertext, key):
    # extract iv and ciphertext
    iv = received_ciphertext[:16]
    ciphertext = received_ciphertext[16:] 

    # recover padded ciphertext
    aes_256_cbc_cipher = Cipher(AES(key), CBC(iv))
    recovered_padded_plaintext = aes_256_cbc_cipher.decryptor().update(ciphertext)

    # remove padding
    pkcs7_unpadder = padding.PKCS7(AES.block_size).unpadder()
    recovered_plaintext = pkcs7_unpadder.update(recovered_padded_plaintext) + pkcs7_unpadder.finalize()

    return recovered_plaintext

def rsa_decrypt_to_list(ciphertext):
    with open("pr_keys.txt", "r") as file:
        d, n = int(file.readline().strip()), int(file.readline())
        plaintext_encoded = []
        for b in ciphertext:
            plaintext_encoded.append(pow(b, d, n))

        return plaintext_encoded # given that the original aes_key is in a string of bytes, we need to now turn this back into said string of bytes from the int it was

def string_list_to_byte_string(list):
    output = b""
    for i in list:
        output += int.to_bytes(i)
    
    return output

def main():
    if (not os.path.isfile("transmitted_message.txt") or not os.path.isfile("pr_keys.txt")):
        print("Relevant file(s) is missing.")
        quit()
    
    # obtaining relevant info
    received_ciphertext, mac, enc_key = None, None, []
    with open("transmitted_message.txt", "rb") as file:
        #enc_key = file.readline()
        #mac = file.readline()
        received_ciphertext = file.read()

    with open("transmitted_mac.txt", "rb") as file:
        mac = file.read()
    
    with open("transmitted_key.txt", "r") as file:
        line = file.readline()
        while (line):
            enc_key.append(int(line))
            line = file.readline()

    # rsa obtain car keys for aes!! (and mac)
    enc_key_decrypted = string_list_to_byte_string(rsa_decrypt_to_list(enc_key))
    
    # hmac verification!!!
    try:
        verify_hmac_sha_256_tag(mac, received_ciphertext, enc_key_decrypted)
        print("mac and key is valid!")
    except InvalidSignature:
        assert False
    else:
        # aes decrypt message and output to console!!
        recovered_plaintext = aes_256_cbc_decrypt(received_ciphertext, enc_key_decrypted)
        print(recovered_plaintext)

main()