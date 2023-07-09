import os
import tkinter as tk
from tkinter import filedialog
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


def save_text_to_file(text, filename):
    with open(filename, 'w') as file:
        file.write(text)
        
        
def get_rsa_key_from_file(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    # Remove the first and last lines
    lines = lines[1:-1]

    # Join the remaining lines into a single string
    string_contents = ''.join(lines)

    return string_contents
def write_to_file(file_path, data):
    with open(file_path, 'a') as file:
        file.write(data + '\n')


def read_file(file_path):
    with open(file_path, 'r') as file:
        file_contents = file.read()

    return file_contents


def phase1():
    #select file
    current_directory = os.getcwd()
    file_path = filedialog.askopenfilename()
    file_name = os.path.basename(file_path)
    file_name = file_name.split(".", 1)[0] 
    aes_Ks_key_name = file_name + "_ks_key.txt"
    #delete_file(file_path)
    print(file_path)
    
    #generate aes key / Ks key
    aes_key = aes.generate_aes_key()
    
    #encrypt file
    aes_Ks_key_path = current_directory + "\\encryption\\aes_encrypted\\" + aes_Ks_key_name 
    save_text_to_file(str(aes_key),aes_Ks_key_path)
    aes.encrypt_file(file_path,aes_key)
    
    # Generate a new RSA key pair
    private_key_path= current_directory+"\\encryption\\rsa\\private_key.pem"
    public_key_path = current_directory+"\\encryption\\rsa\\public_key.pem"
    rsa_alg.generate_rsa_key_pair(private_key_path, public_key_path)


    #Encrypt Ks key using rsa public key
    # Encrypt the text file using the public key to => Kx key
    output_path = current_directory+"\\encryption\\rsa\\"+ file_name + "_rsa_enc.txt"
    rsa_alg.encrypt_file_rsa(aes_Ks_key_path, public_key_path, output_path)
    decrypt_output = current_directory+"\\encryption\\rsa\\"+ file_name + "_rsa_dec.txt"
    rsa_alg.decrypt_file(output_path,private_key_path,decrypt_output)
    Kx_key = read_file(current_directory+"\\encryption\\rsa\\"+ file_name + "_rsa_dec.txt")
    
    #Encrypt K key using SHA1
    write_to_file(current_directory+"\\encryption\\"+file_name+".xml",Kx_key)
    
    Kprivate = get_rsa_key_from_file(private_key_path)
    HKprivate = sha1_sha256.compute_sha1_hash(Kprivate)
    print(HKprivate)
    write_to_file(current_directory+"\\encryption\\"+file_name+".xml",HKprivate)

def phase2():
    #select file
    current_directory = os.getcwd()
    file_path = filedialog.askopenfilename()
    file_name = os.path.basename(file_path)
    file_name = file_name.split(".", 1)[0] 
    aes_Ks_key_name = file_name + "_ks_key.txt"
    # print(aes_Ks_key_name)
    #input Kprivate key
    k_private_key =  input_phase2.get()
    if k_private_key == '':
        return
    print(k_private_key)


    
    
    
def select_file():
    file_path = filedialog.askopenfilename()
    print(file_path)

button_select_file = tk.Button(root, text="Select File", command=select_file)
button_phase1 = tk.Button(root, text="Phase 1", command=phase1)
button_phase2 = tk.Button(root, text="Phase 2", command=phase2)
input_phase2 = tk.Entry(root, width=20)


button_select_file_decryption = tk.Button(root, text="Select file to decrypt", command=select_file)

# button_select_file.pack()
button_phase1.pack()
button_phase2.pack()
tk.Label(root, text="Enter Kprivate key").pack()

input_phase2.pack()
# button_select_file_decryption.pack()


# Run the GUI application
root.mainloop()
