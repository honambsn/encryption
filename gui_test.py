# import tkinter as tk
# from tkinter import ttk
# from tkinter import filedialog
# from tkinter import messagebox

# def open_file():
#     file_path = filedialog.askopenfilename()
#     if file_path:
#         with open(file_path, 'r') as file:
#             content = file.read()
#             messagebox.showinfo("File Content", content)

#             # Do something with the file content
#             print(content)

# def main():
#     window = tk.Tk()
#     window.title("File Reader App")
#     window.geometry("400x300")
#     window.resizable(False, False)

#     style = ttk.Style()
#     style.configure("TButton",
#                     foreground="white",
#                     background="blue",
#                     font=("Helvetica", 12, "bold"),
#                     padding=10)
#     style.map("TButton",
#               foreground=[('active', 'white')],
#               background=[('active', 'blue')])

#     label = tk.Label(window, text="File Reader App", font=("Helvetica", 18, "bold"))
#     label.pack(pady=20)

#     button = ttk.Button(window, text="Open File", command=open_file)
#     button.pack(pady=10)
    
#     text = tk.Text(window, font=("Helvetica", 12))
#     text.pack(expand=True, fill="both")

#     window.mainloop()

# if __name__ == "__main__":
#     main()
import tkinter as tk
from tkinter import ttk, filedialog

def open_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'r') as file:
            content = file.read()
            text_area.delete('1.0', tk.END)
            text_area.insert(tk.END, content)
def main():
    window = tk.Tk()
    window.title("File Viewer")

    # Create and configure the Open File button
    open_button = ttk.Button(window, text="Open File", command=open_file)
    open_button.pack(pady=10)

    # Create a frame to hold the text area
    text_frame = ttk.Frame(window)
    text_frame.pack(padx=10, pady=10)

    text_area = tk.Text(text_frame, width=40, height=10)
    text_area.pack()

    window.mainloop()
if __name__=="main":
    main()