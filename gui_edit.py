import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import enc_alg


def update_label(new_text):
    label.config(text=new_text)

def other_function():
    # Perform some calculations or actions
    text = "Plaintext"
    update_label(text)

def browse_file():
    file_path = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)
def open_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'r') as file:
            content = file.read()
            encrypt_file_handler(content)
            print(content)
            text_area.delete('1.0', tk.END)
            text_area.insert(tk.END, content)
def encrypt_file_handler(content):
    #file_path = file_entry.get()
    print("content " + content)
    
    # Call the encryption functions from the "enc_alg" module
    # Example usage:
    # enc_alg.generate_aes_key()
    # enc_alg.encrypt_file(file_path)
    # enc_alg.generate_rsa_keypair()
    # enc_alg.encrypt_with_rsa_public_key()
    # enc_alg.save_metadata_file()
    # enc_alg.export_private_key()

    # Rest of the code...

# Create the GUI root
root = tk.Tk()
root.title("File Encryption")

# Rest of the GUI code...
# root = tk.Tk()
# root.title("File Viewer")

    # Create and configure the Open File button
open_button = ttk.Button(root, text="Open File", command=open_file)
open_button.pack(pady=10)

    # Create a frame to hold the text area
text_frame = ttk.Frame(root)
text_frame.pack(padx=10, pady=10)

text_area = tk.Text(text_frame, width=40, height=10)
text_area.pack()


label = tk.Label(root, text="", font=('Arial',14),bg="lightgray", fg="black", width=20, height=2, relief="solid", padx=10, pady=5)
label.pack(fill=tk.BOTH, padx=5, pady=2)
label.pack()



field_labels = {}

field_groups = [
    {
        "name": "AES",
        "fields": ["Text", "Key", "Enc", "Denc"]
    },
    {
        "name": "RSA",
        "fields": ["Text", "Key", "Enc", "Denc"]
    },
    {
        "name": "SHA-1",
        "fields": ["Text", "Key", "Enc", "Denc"]
    }
]



def display_values(field_groups):
    field_groups = [
        {
            "name": "AES",
            "fields": ["Text", "Key", "Enc", "Denc"]
        },
        {
            "name":"RSA",
            "fields": ["Text", "Key", "Enc", "Denc"]
        },
        {
            "name": "SHA-1",
            "fields": ["Text", "Key", "Enc", "Denc"]
        }
    ]
    
    
        
    # print("field_groups[1][0]", field_groups[1][0])
    for group in field_groups:
        group_name = group["name"]
        fields = group["fields"]

        print(f"{group_name} Group:")
        for field in fields:
            value = field_labels[group_name][field].cget("text")
            print(f"{field}: {value}")
        print("")


root.geometry("400x800")
root.resizable(False,False)


for group in field_groups:
    group_name = group["name"]
    fields = group["fields"]

    group_frame = ttk.LabelFrame(root, text=group_name)
    group_frame.pack(padx=10, pady=10)

    field_labels[group_name] = {}

    for field in fields:
        label = tk.Label(group_frame, text=f"{group_name} {field} Value", relief="groove")
        label.pack(fill=tk.BOTH, padx=5, pady=2)

        field_labels[group_name][field] = label



display_button = ttk.Button(root, text="Display Values", command=display_values(field_groups))
display_button.pack(pady=10)

root.mainloop()

