from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def generate_aes_key():
    # Generate a random 256-bit key
    key = get_random_bytes(32)
    return key

def encrypt_file(file_path, key):
    # Read the contents of the file
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    # Create an AES cipher object with the key
    cipher = AES.new(key, AES.MODE_EAX)

    # Encrypt the plaintext
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Write the encrypted data to a new file
    encrypted_file_path = file_path + "_aes_encrypted.enc"
    with open(encrypted_file_path, 'wb') as file:
        [file.write(x) for x in (cipher.nonce, tag, ciphertext)]

    print("File encrypted successfully.")

def decrypt_file(file_path, key):
    # Read the contents of the encrypted file
    with open(file_path, 'rb') as file:
        nonce, tag, ciphertext = [file.read(x) for x in (16, 16, -1)]

    # Create an AES cipher object with the key
    cipher = AES.new(key, AES.MODE_EAX, nonce)

    # Decrypt the ciphertext
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    # Write the decrypted data to a new file
    decrypted_file_path = file_path + "_aes_decrypted.dec"
    with open(decrypted_file_path, 'wb') as file:
        file.write(plaintext)

    print("File decrypted successfully.")

# # Key generation
# key = generate_aes_key()

# import os 
# current_directory = os.getcwd()

# print(current_directory)

# current_directory += "\\encryption\\plaintext.txt"
# # Encryption
# file_path = current_directory
# encrypt_file(file_path, key)

# # Decryption
# encrypted_file_path = file_path + ".enc"
# decrypt_file(encrypted_file_path, key)


