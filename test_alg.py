# field_groups = [
# {
# "name": "AES",
# "fields": ["Text", "Key", "Enc", "Denc"]
# },
# {
# "name":"RSA",
# "fields": ["Text", "Key", "Enc", "Denc"]
# },
# {
# "name": "SHA-1",
# "fields": ["Text", "Key", "Enc", "Denc"]
# }
# ]
# print("field_groups[0]", field_groups[0])
# print(type(field_groups))

# print("len field_groups[0]: ", len(field_groups[0:1]))

# print("field_groups[0]", field_groups[0])

# print(" type of field_groups[0]", type(field_groups[0]))

# name_value = field_groups[1]["fields"][0]
# print(f"Name: {name_value}")



# arr = [
    
# ]

# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.backends import default_backend

# def generate_rsa_key_pair(private_key_path, public_key_path):
#     # Generate a new RSA key pair
#     private_key = rsa.generate_private_key(
#         public_exponent=65537,
#         key_size=2048,
#         backend=default_backend()
#     )
    
#     # Save the private key to file
#     with open(private_key_path, "wb") as private_key_file:
#         private_key_pem = private_key.private_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PrivateFormat.PKCS8,
#             encryption_algorithm=serialization.NoEncryption()
#         )
#         private_key_file.write(private_key_pem)
    
#     # Extract the public key from the private key
#     public_key = private_key.public_key()
    
#     # Save the public key to file
#     with open(public_key_path, "wb") as public_key_file:
#         public_key_pem = public_key.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         )
#         public_key_file.write(public_key_pem)

# def encrypt_file_rsa(file_path, public_key_path, output_path):
#     # Load the public key from file
#     with open(public_key_path, "rb") as key_file:
#         public_key = serialization.load_pem_public_key(
#             key_file.read(),
#             backend=default_backend()
#         )
    
#     # Read the file content
#     with open(file_path, "rb") as file:
#         file_content = file.read()
    
#     # Encrypt the file content using RSA encryption
#     encrypted_content = public_key.encrypt(
#         file_content,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
    
#     # Write the encrypted content to the output file
#     with open(output_path, "wb") as output_file:
#         output_file.write(encrypted_content)
        


# def decrypt_file(encrypted_file, private_key_file, decrypted_file):
#     # Load the private key from file
#     with open(private_key_file, "rb") as key_file:
#         private_key = serialization.load_pem_private_key(
#             key_file.read(),
#             password=None,
#             backend=default_backend()
#         )

#     # Read the encrypted file
#     with open(encrypted_file, "rb") as file:
#         encrypted_data = file.read()

#     # Decrypt the encrypted data using RSA private key
#     decrypted_data = private_key.decrypt(
#         encrypted_data,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )

#     # Write the decrypted data to a new file
#     with open(decrypted_file, "wb") as file:
#         file.write(decrypted_data)


# # Generate a new RSA key pair
# private_key_path = "D:/Ba Nam/Own project/Practice/encryption/rsa/private_key.pem"
# public_key_path = "D:/Ba Nam/Own project/Practice/encryption/rsa/public_key.pem"
# generate_rsa_key_pair(private_key_path, public_key_path)

# # Encrypt the text file using the public key
# file_path = "D:/Ba Nam/Own project/Practice/encryption/plaintext.txt"
# output_path = "D:/Ba Nam/Own project/Practice/encryption/rsa/encrypted_file.txt"
# encrypt_file_rsa(file_path, public_key_path, output_path)


# encrypted_file = "D:/Ba Nam/Own project/Practice/encryption/rsa/encrypted_file.txt"
# private_key_path = "D:/Ba Nam/Own project/Practice/encryption/rsa/private_key.pem"
# decrypted_file = "D:/Ba Nam/Own project/Practice/encryption/rsa/decrypted.txt"
# decrypt_file(encrypted_file, private_key_path, decrypted_file)


# import os

# # Specify the existing directory path
# existing_directory = "D:/Ba Nam/Own project/Practice/encryption"

# # Specify the name of the new folder
# new_folder_name = "new_folder"

# # Create the complete path for the new folder
# new_folder_path = os.path.join(existing_directory, new_folder_name)

# # Create the new folder
# os.makedirs(new_folder_path)
# print(f"New folder '{new_folder_path}' created successfully.")


    
# import os    
# def save_text_to_file(text, filename):
#     with open(filename, 'w') as file:
#         file.write(text)

# current_directory = os.getcwd()

#     # Example usage
# text = "This is the content of the file."
# filename = current_directory+"\\encryption\\rsa\\output.txt"
# save_text_to_file(text, filename)
    
# import tkinter as tk
# from tkinter import filedialog
# import os

# # Create a Tkinter window
# root = tk.Tk()

# def open_file():
#     # Open the file dialog and get the selected file path
#     file_path = filedialog.askopenfilename()

#     # Get the filename from the file path
#     file_name = os.path.basename(file_path)

#     # Print the filename
#     print("Selected file:", file_name)
#     print(type(file_name))
#     file_name = file_name.split(".", 1)[0]
#     print(file_name)

# # Create a button to open the file dialog
# button = tk.Button(root, text="Open File", command=open_file)
# button.pack()

# # Run the Tkinter event loop
# root.mainloop()



# import hashlib

# def compute_sha1_hash(string):
#     # Create a SHA-1 hash object
#     sha1_hash = hashlib.sha1()

#     # Update the hash object with the string
#     sha1_hash.update(string.encode('utf-8'))

#     # Get the hexadecimal representation of the hash value
#     hash_value = sha1_hash.hexdigest()

#     return hash_value

# def compute_sha256_hash(string):
#     # Create a SHA-256 hash object
#     sha256_hash = hashlib.sha256()

#     # Update the hash object with the string
#     sha256_hash.update(string.encode('utf-8'))

#     # Get the hexadecimal representation of the hash value
#     hash_value = sha256_hash.hexdigest()

#     return hash_value

# # Read the string from a text file
# file_path = "D:\\Ba Nam\\Own project\\Practice\\encryption\\rsa\\plaintext_rsa_enc.txt"
# with open(file_path, 'r') as file:
#     string = file.read()

# # Compute the SHA-1 hash
# sha1_hash = compute_sha1_hash(string)
# print("SHA-1 Hash:", sha1_hash)

# # Compute the SHA-256 hash
# sha256_hash = compute_sha256_hash(string)
# print("SHA-256 Hash:", sha256_hash)

# def remove_first_last_row(file_path):
#     with open(file_path, 'r') as file:
#         lines = file.readlines()

#     # Remove the first and last lines
#     lines = lines[1:-1]

#     # Join the remaining lines into a single string
#     string_contents = ''.join(lines)

#     return string_contents


# # Example usage
# file_path = 'D:\\Ba Nam\\Own project\\Practice\\encryption\\rsa\\private_key.pem'

# string_from_file = remove_first_last_row(file_path)
# print("String from file (without first and last row):", string_from_file)


import os
import importlib.util

# Get the path to the current script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Construct the path to the alg folder relative to the script
alg_path = os.path.join(script_dir, 'alg')

# Import the aes module from the alg folder
aes_spec = importlib.util.spec_from_file_location('aes', os.path.join(alg_path, 'aes.py'))
aes = importlib.util.module_from_spec(aes_spec)
aes_spec.loader.exec_module(aes)

# Import the enc_alg module from the alg folder
enc_alg_spec = importlib.util.spec_from_file_location('enc_alg', os.path.join(alg_path, 'enc_alg.py'))
enc_alg = importlib.util.module_from_spec(enc_alg_spec)
enc_alg_spec.loader.exec_module(enc_alg)

# Import the rsa_alg module from the alg folder
rsa_alg_spec = importlib.util.spec_from_file_location('rsa_alg', os.path.join(alg_path, 'rsa_alg.py'))
rsa_alg = importlib.util.module_from_spec(rsa_alg_spec)
rsa_alg_spec.loader.exec_module(rsa_alg)

# Import the sha1_sha256 module from the alg folder
sha1_sha256_spec = importlib.util.spec_from_file_location('sha1_sha256', os.path.join(alg_path, 'sha1_sha256.py'))
sha1_sha256 = importlib.util.module_from_spec(sha1_sha256_spec)
sha1_sha256_spec.loader.exec_module(sha1_sha256)

# Now you can use functions and variables from the imported modules
key = aes.generate_aes_key()
print(key)
# enc_alg.some_function()
# rsa_alg.generate_key_pair()
# sha1_sha256.compute_sha1_hash()
