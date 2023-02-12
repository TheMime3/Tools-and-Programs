"Creator: TheMime3"
"With help from: ChatGPT, loadingError117, adamclmns"

import tkinter as tk
import string
import random


def encode(plaintext, key1, key2):
    alphabet = string.ascii_letters
    encrypted_text = ""
    for i, char in enumerate(plaintext):
        if char in alphabet:
            char_index = (alphabet.index(char) + key1 + key2) % len(alphabet)
            encrypted_text += alphabet[char_index]
        else:
            encrypted_text += "_"
    return encrypted_text

def decode(encrypted_text, key1, key2):
    alphabet = string.ascii_letters
    plaintext = ""
    for i, char in enumerate(encrypted_text):
        if char in alphabet:
            char_index = (int(alphabet.index(char))) - int(key1) - int(key2) % len(alphabet)
            plaintext += alphabet[char_index]
        else:
            plaintext += " "
    return plaintext

def on_encrypt_clicked():
    plaintext = plaintext_entry.get()
    alphabet = string.ascii_letters
    key1 = random.randint(1, len(alphabet) - 1)
    key2 = random.randint(1, len(alphabet) - 1)
    encrypted_text = encode(plaintext, key1, key2)
    
    encrypted_text_entry.delete(0, tk.END)
    encrypted_text_entry.insert(0, encrypted_text)

    key1_entry.delete(0, tk.END)
    key1_entry.insert(0, key1)

    key2_entry.delete(0, tk.END)   
    key2_entry.insert(0, key2)

def on_decrypt_clicked():
    encrypted_text = encrypted_text_entry.get()
    key1 = key1_entry.get()
    key2 = key2_entry.get()
    decrypted_text = decode(encrypted_text, key1, key2)
    decrypted_text_entry.delete(0, tk.END)
    decrypted_text_entry.insert(0, decrypted_text)

def on_copy_all():
    copyall_text_entry.delete(0, tk.END)
    serializedString = encrypted_text_entry.get()+" | ["+key1_entry.get()+":"+key2_entry.get()+"]"
    copyall_text_entry.insert(0,serializedString)

def on_clear_all():
    plaintext_entry.delete(0, tk.END)
    key1_entry.delete(0, tk.END)
    key2_entry.delete(0, tk.END)
    encrypted_text_entry.delete(0, tk.END)
    decrypted_text_entry.delete(0, tk.END)
    copyall_text_entry.delete(0, tk.END)


root = tk.Tk()
root.geometry("800x400")

# Labels
plaintext_label = tk.Label(root, text="Text to be Encrypted:")
key1_label = tk.Label(root, text="Key 1:")
key2_label = tk.Label(root, text="Key 2:")
encrypted_text_label = tk.Label(root, text="Encrypted Text:")
decrypted_text_label = tk.Label(root, text="Decrypted Text:")
copyall_text_label = tk.Label(root, text="Copy:")

# Entry widgets
plaintext_entry = tk.Entry(root)
key1_entry = tk.Entry(root)
key2_entry = tk.Entry(root)
encrypted_text_entry = tk.Entry(root)
decrypted_text_entry = tk.Entry(root)
copyall_text_entry = tk.Entry(root)

# Buttons
encrypt_button = tk.Button(root, text="Encrypt", command=on_encrypt_clicked)
decrypt_button = tk.Button(root, text="Decrypt", command=on_decrypt_clicked)
copyall_button = tk.Button(root, text="Copy All Encrypted", command=on_copy_all)
clearall_button = tk.Button(root, text="Clear all", command=on_clear_all)

# Grid layout
plaintext_label.grid(row=0, column=0)
key1_label.grid(row=1, column=0)
key2_label.grid(row=2, column=0)
encrypted_text_label.grid(row=3, column=0)
decrypted_text_label.grid(row=4, column=0)

plaintext_entry.grid(row=0, column=1)
key1_entry.grid(row=1, column=1)
key2_entry.grid(row=2, column=1)
encrypted_text_entry.grid(row=3, column=1)
decrypted_text_entry.grid(row=4, column=1)
copyall_text_entry.grid(row=6, column=1)

encrypt_button.grid(row=5, column=0)
decrypt_button.grid(row=5, column=1)
copyall_button.grid(row=6, column=0)

clearall_button.grid(row=7, column=0)

root.mainloop()
