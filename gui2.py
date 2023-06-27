import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import enc_alg

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


# Run the GUI
root.mainloop()
