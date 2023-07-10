from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os


def get_file_name(file_path):
    file_name = os.path.basename(file_path)
    file_name = file_name.split(".", 1)[0] 
    return file_name

def generate_aes_key():
    # Generate a random 256-bit key
    key = get_random_bytes(32)
    print("->AES key: ", key, len(key), type(key))
    return key

def encrypt_file(file_path, key):
    # Read the contents of the file
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    # Create an AES cipher object with the key
    cipher = AES.new(key, AES.MODE_EAX)

    # Encrypt the plaintext
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    #export file name
    file_name = get_file_name(file_path)
    
    # Write the encrypted data to a new file
    encrypted_file_path = file_name + "_aes_encrypted.enc"
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
    
    #export file name
    file_name = get_file_name(file_path)

    # Write the decrypted data to a new file
    decrypted_file_path = file_name + "_aes_decrypted.dec"
    with open(decrypted_file_path, 'wb') as file:
        file.write(plaintext)

    print("File decrypted successfully.")

# # Key generation
# key = generate_aes_key()


# # Encryption
# file_path = current_directory
# encrypt_file(file_path, key)

# # Decryption
# encrypted_file_path = file_path + ".enc"
# decrypt_file(encrypted_file_path, key)


