import os
import tkinter as tk
from tkinter import filedialog
import enc_alg  # Import your encryption algorithms from enc_alg.py
import rsa_alg

# Create the GUI application
root = tk.Tk()
root.title("File Encryption")
root.geometry("400x300")
root.resizable(False,False)

# Create the GUI elements
label_file = tk.Label(root, text="Select a file to encrypt:")
label_file.pack()


def delete_file(file_path):
    file_path += ".enc"
    try:
        os.remove(file_path)
        print(f"File '{file_path}' deleted successfully.")
    except OSError as error:
        print(f"Error occurred while deleting file '{file_path}': {error}")

def encrypt_file_aes():
    # Get the selected file
    file_path = filedialog.askopenfilename()
    delete_file(file_path)
    print(file_path)
    
    aes_key = enc_alg.generate_aes_key()
    
    # Call the encryption function from enc_alg.py to encrypt the file
    enc_alg.encrypt_file_aes(file_path,aes_key)
    
    

    # Call the encryption function from enc_alg.py to encrypt the file
    
    

def encrypt_file_rsa():
    # Get the selected file
    file_path = filedialog.askopenfilename()
    #delete_file(file_path)
    print(file_path)
    
    
    current_directory = os.getcwd()


    # Generate a new RSA key pair
    private_key_path= current_directory+"\\encryption\\rsa\\private_key.pem"
    public_key_path = current_directory+"\\encryption\\rsa\\public_key.pem"
    rsa_alg.generate_rsa_key_pair(private_key_path, public_key_path)

    # Encrypt the text file using the public key
    # file_path = current_directory+"\\encryption\\plaintext.txt"
    output_path = current_directory+"\\encryption\\rsa\\encrypted_file.txt"
    rsa_alg.encrypt_file_rsa(file_path, public_key_path, output_path)


    encrypted_file = current_directory+"\\encryption\\rsa\\encrypted_file.txt"
    private_key_path = current_directory+"\\encryption\\rsa\\private_key.pem"
    decrypted_file = current_directory+"\\encryption\\rsa\\decrypted.txt"
    rsa_alg.decrypt_file(encrypted_file, private_key_path, decrypted_file)

    
    # Call the encryption function from enc_alg.py to encrypt the file
    
    
    

    # Call the encryption function from enc_alg.py to encrypt the file
    
    
    
    
def encrypt_file_sha():
    # Get the selected file
    file_path = filedialog.askopenfilename()
    delete_file(file_path)
    print(file_path)
    
    aes_key = enc_alg.generate_aes_key()
    
    # Call the encryption function from enc_alg.py to encrypt the file
    enc_alg.encrypt_file_aes(file_path,aes_key)
    
    

    # Call the encryption function from enc_alg.py to encrypt the file
    
    

def select_file():
    file_path = filedialog.askopenfilename()
    print(file_path)

button_select_file = tk.Button(root, text="Select File", command=select_file)
button_encrypt_aes = tk.Button(root, text="Encrypt File Using AES", command=encrypt_file_aes)
button_encrypt_rsa = tk.Button(root, text="Encrypt File Using RSA", command=encrypt_file_rsa)
button_encrypt_sha = tk.Button(root, text="Encrypt File Using SHA", command=encrypt_file_sha)

button_select_file.pack()
button_encrypt_aes.pack()
button_encrypt_rsa.pack()
button_encrypt_sha.pack()

# Run the GUI application
root.mainloop()
