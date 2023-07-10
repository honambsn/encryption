import os
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

import importlib.util
import shutil


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
# label_file = tk.Label(root, text="Select a file to encrypt:")
# label_file.pack()
label_file = tk.Label(root, text="\n\n\n")
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

def add_header_footer(file_path):
    first_line_content="-----BEGIN PRIVATE KEY-----"
    last_line_content="-----END PRIVATE KEY-----"
    first_line= ""
    # Read the existing content of the file
    with open(file_path, 'r') as file:
        first_line = file.readline().strip()
        existing_content = file.readlines()
    
    # Open the file in write mode and truncate its contents
    with open(file_path, 'w') as file:
            # Write the new first line content
        #file.write(first_line_content)

            # Write the original content between the new first and last lines
        for line in existing_content:
            file.write(line)

            # Write the new last line content
        file.write(last_line_content + '\n')
    
    
    # Read the existing contents of the file
    with open(file_path, 'r') as file:
        existing_content = file.read()

    # Split the existing content into lines
    lines = existing_content.splitlines()

    # Create the new content by concatenating the new content, line break, and the existing lines
    new_content = first_line_content + '\n' + '\n'.join(lines)

    # Write the new content back to the file
    with open(file_path, 'w') as file:
        file.write(new_content)
        
    ###########
    # with open(file_path, 'r') as file:
    #     existing_content = file.read()

    # # Create the new content by concatenating the new content, line break, and existing content
    # new_content = first_line_content + '\n' + existing_content

    # # Write the new content back to the file
    # with open(file_path, 'w') as file:
    #     file.write(new_content)

def phase1():
    #select file
    current_directory = os.getcwd()
    file_path = filedialog.askopenfilename()
    file_name = os.path.basename(file_path)
    file_name = file_name.split(".", 1)[0] 
    aes_Ks_key_name = file_name + "_Ks_key.txt"
    #delete_file(file_path)
    print(file_path)
    
    #generate aes key / Ks key
    Ks_key = aes.generate_aes_key()
    
    #encrypt file p->c 
    aes_Ks_key_path = current_directory + "\\aes_encrypted\\" + aes_Ks_key_name 
    save_text_to_file(str(Ks_key),aes_Ks_key_path)
    aes.encrypt_file(file_path,Ks_key)
    
    # Generate a new RSA key pair
    private_key_path= current_directory+"\\rsa\\Kprivate_key.pem" #Kprivate
    public_key_path = current_directory+"\\rsa\\Kpublic_key.pem" #Kpublic
    rsa_alg.generate_rsa_key_pair(private_key_path, public_key_path)
    


    #Encrypt Ks key using rsa public key
    # Encrypt the text file using the public key to => Kx key
    #the de/encrypted file will be stored in rsa folder
    output_path = current_directory+"\\rsa\\"+ file_name + "'s Kx_rsa_enc.txt"
    rsa_alg.encrypt_file_rsa(aes_Ks_key_path, public_key_path, output_path)
    
    
    decrypt_output = current_directory+"\\rsa\\"+ file_name + "'s Kx_rsa_dec.txt"
    rsa_alg.decrypt_file(output_path,private_key_path,decrypt_output)
    Kx_key = read_file(current_directory+"\\rsa\\"+ file_name + "'s Kx_rsa_dec.txt") #get Kx
    
    #save    to file
    write_to_file(current_directory+"\\"+file_name+".xml",Kx_key)
    
    #get Kprivate
    Kprivate = get_rsa_key_from_file(private_key_path)
    
    #Encrypt K key using SHA1
    HKprivate = sha1_sha256.compute_sha1_hash(Kprivate)
    print(HKprivate)
    #save SHA-1 encrypted Kprivate to file
    write_to_file(current_directory+"\\"+file_name+".xml",HKprivate)
    
    
    #generate Kprivate for user
    folder_name = "User_output"
    #save Kprivate for user
    write_to_file(current_directory+"\\"+ folder_name+"\\" + file_name +"'s Kprivate_key.txt",HKprivate)




def check_user_Kprivate(input_Kprivate,file_name):
    org_HK_private_key = ""
    #get Hk_private_key from  "file_name".xml
    file_name += ".xml"
    # Open the file in read mode
    with open(file_name, 'r') as file:
        print('open to check: ', file_name)
        lines = file.readlines()
    #get last row aka latest HK_private_key of file
    org_HK_private_key = lines[-1].strip()
    
    #hash usr input key to compare
    user_Kprivate_sha1 = sha1_sha256.compute_sha1_hash(input_Kprivate) 
    print("check: ",user_Kprivate_sha1,org_HK_private_key)
    return org_HK_private_key == user_Kprivate_sha1


#get Kprivate by select file
def Kprivate_select_file():
    #select file
    current_directory = os.getcwd()
    file_path = filedialog.askopenfilename(title="select kPrivate file")
    file_name = os.path.basename(file_path)
    file_name = file_name.split(".", 1)[0] 
    print("file_name:", file_name)
    messagebox.showinfo("",'select success')
    return get_rsa_key_from_file(file_path),file_path
    
#get usr Kprivate key by input
def Kprivate_input():
    #input Kprivate key
    k_private_key =  input_phase2.get()
    if k_private_key == '':
        # messagebox.showinfo("Warning", f"You entered: {input_text}")
        messagebox.showwarning("Warning", f"Cant be empty")
    print("input k_private_key: \n",k_private_key)
    messagebox.showinfo("","input success")
    return k_private_key
    # Kprivate_check_value = check_user_Kprivate()
    # print(Kprivate_check_value)




def run_decrypt(file_name,Kprivate_value,usr_key_file_path,enc_file_path):
    # Open the file in read mode
    #open xml file    
    with open(file_name+'.xml', 'r') as file:
        print(file_name+'.xml')
        lines = file.readlines()
    
    #get 2nd latest row aka latest Kx of file
    Kx_key = lines[-2].strip()
    print('Kx: ', Kx_key)
    save_text_to_file(Kx_key,'Kx_key.txt')
    print(Kprivate_value)
    
    # save_text_to_file(Kprivate_value,"Usr's Kprivate value.pem")
    
    
    #check if sha1 is as similar as Hk
    if check_user_Kprivate(Kprivate_value,file_name):
        messagebox.showinfo("","SIMILAR")
    else:
        messagebox.showwarning("","DIFFERENT")
        
    
    current_directory = os.getcwd()
    
    #encrypted_file=current_directory + '\\Kx_key.txt'
    encrypted_file= current_directory+"\\rsa\\"+ file_name + "'s Kx_rsa_enc.txt"
    # private_key_file = current_directory+"\\Usr's Kprivate value.pem"
    private_key_file = usr_key_file_path
    decrypt_output =  file_name + "'s Kx_dec.txt"
    decrypted_file = current_directory+"\\"+decrypt_output
    output_path = current_directory+"\\rsa\\"+ file_name + "'s Kx_rsa_enc.txt"
    
    
    print("dir: ",current_directory + '\\Kx_key.txt')
    print("dir: ",current_directory+"\\Usr's Kprivate value.pem")
    print("dir: ",current_directory+"\\"+decrypt_output)
    decrypt_output = current_directory+"\\rsa\\"+ file_name + "'ssssssssss Kx_rsa_dec.txt"
    # add_header_footer(current_directory+"\\Usr's Kprivate value.pem")
    #decrypt user Kx file to get Ks
    # rsa_alg.decrypt_file(current_directory + '\\Kx_key.txt',current_directory+"\\Usr's Kprivate value.pem",current_directory+"\\"+decrypt_output)
    rsa_alg.decrypt_file(encrypted_file, private_key_file, decrypt_output)

    if os.path.exists(decrypt_output):
        messagebox.showinfo("Successfully",f'Output Decrypted Kx file: \n "{decrypt_output}"')
        
    original_Ks = ""
    with open(decrypt_output, 'r') as file:
        lines = file.readlines()    
        print("test: ",str(lines), type(lines), len(lines))
        tmp = lines[0].replace("\\\\", "\\")
        print("\t=>: ", tmp, len(tmp))
    #     original_Ks = tmp
    #     original_Ks = bytes(original_Ks)
    #     print("\t=>: ", original_Ks)

    # print(original_Ks, type(original_Ks))
    print(enc_file_path)
    aes.decrypt_file(enc_file_path,tmp)
    
        
        
        
    
    
    
    
    

#CONFIRM    
def confirm_run(file_name,file_path):
    usr_Kprivate_key = ""
    print("confirm_run",file_name)
    enc_file_path = file_path
    # while Kprivate_input() == "" and Kprivate_select_file() == "":
    #     messagebox.showwarning("No input Kprivate key")
        
    usr_Kprivate_key,usr_kPrivate_file_path = Kprivate_select_file()
    print(usr_Kprivate_key)
    # if Kprivate_input() == "":
    #     usr_Kprivate_key = Kprivate_select_file()
        
    # elif Kprivate_select_file() == "":
    #     usr_Kprivate_key = Kprivate_input()

    print('run decrypt', file_name)
    print('Kprivate value: ',usr_Kprivate_key)
    
    print(usr_kPrivate_file_path)
    run_decrypt(file_name,usr_Kprivate_key,usr_kPrivate_file_path,enc_file_path)
            
    

    
def select_enc_file():
    file_path = filedialog.askopenfilename(title='select enc file')
    print(file_path)
    file_name = os.path.basename(file_path)
    print(file_name)
    file_name = file_name.split("_")[0]
    print("file_name:",file_name)
    confirm_run(file_name,file_path)
    
    
def cls_window():
    root.quit()
    
    
    
        

    

# button_select_file = tk.Button(root, text="Select File", command=select_file)
button_phase1 = tk.Button(root, text="Choose file to encrypt", command=phase1)
button_phase2 = tk.Button(root, text="Choose Kprivate file to decrypt", command=Kprivate_select_file)
button_phase2_2 = tk.Button(root, text="Confirm input", command=Kprivate_input, state="disabled")
input_phase2 = tk.Entry(root, width=20,state="disabled")

input_phase2.insert(tk.END, "Maintenance")

button_select_file_decryption = tk.Button(root, text="Select file to decrypt", command=select_enc_file)
btn_confirm = tk.Button(root,text="Confirm decrypt", command=confirm_run)

# button_select_file.pack()
button_phase1.pack()
button_phase2.pack()
tk.Label(root, text="Or enter Kprivate key").pack()
input_phase2.pack()
button_phase2_2.pack()
button_select_file_decryption.pack()

quit_button = tk.Button(root, text="Quit", command=cls_window)    
quit_button.pack()
#btn_confirm.pack()



# button_select_file_decryption.pack()


# Run the GUI application
root.mainloop()
