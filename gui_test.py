import tkinter as tk
from tkinter import ttk

def display_values():
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
    print("field_groups[0]", field_groups[0])
    print(type(field_groups))
    
    print("len field_groups[0]: ", len(field_groups[0][1]))
    
        
    # print("field_groups[1][0]", field_groups[1][0])
    for group in field_groups:
        group_name = group["name"]
        fields = group["fields"]

        print(f"{group_name} Group:")
        for field in fields:
            value = field_labels[group_name][field].cget("text")
            print(f"{field}: {value}")
        print("")

root = tk.Tk()
root.title("Field Values")
root.geometry("400x500")
root.resizable(False,False)

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



display_button = ttk.Button(root, text="Display Values", command=display_values)
display_button.pack(pady=10)

root.mainloop()
