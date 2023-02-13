"Creator: TheMime3"
"With help from: OpenAi, loadingError117, adamclmns"

from tkinter import *
from tkinter import messagebox
from SSL import start_gui
import json
import os
import sys
from cryptography.fernet import Fernet

# update check credentials function
def check_credentials():
    # setup encryption
    userPass = user_entry.get() + ':' + pass_entry.get()
    userPass = userPass.encode('utf-8')
    
    # open the data.json file
    with open(os.path.join(sys.path[0], "data.json"), "r") as f:
        user_data = json.load(f)
    
    # retrieve the secret key and encrypted credentials for the entered username
    secret_key = None
    encrypted_credentials = None
    for key, value in user_data.items():
        if value.get('username') == user_entry.get():
            secret_key_file = value.get('key_file')
            with open(os.path.join(sys.path[0], secret_key_file), "rb") as f:
                secret_key = f.read()
            encrypted_credentials = key.encode('utf-8')
    
    # check if the secret key was retrieved
    if secret_key is None or encrypted_credentials is None:
        messagebox.showerror("Error", "The username or password you entered is incorrect.")
        return

    cipher = Fernet(secret_key)
    decrypted_credentials = cipher.decrypt(encrypted_credentials)
   
    # check if the decrypted credentials match the entered credentials
    if decrypted_credentials.decode('utf-8') == userPass.decode('utf-8'):
        window.destroy()
        start_gui()
    else:
        messagebox.showerror("Error", "The username or password you entered is incorrect.")

# function to create account
def create_account():
    # set up encryption
    userPass = user_entry.get() + ':' + pass_entry.get()
    userPass = userPass.encode('utf-8')

    # generate a new secret key
    secret_key = Fernet.generate_key()

    # write the secret key to a file with a unique name
    key_file_name = user_entry.get() + '.key'
    with open(os.path.join(sys.path[0], key_file_name), "wb") as key_file:
        key_file.write(secret_key)

    cipher = Fernet(secret_key)
    encrypted_text = cipher.encrypt(userPass)

    # open the data.json file
    with open(os.path.join(sys.path[0], "data.json"), "r") as f:
        user_data = json.load(f)

    # add the encrypted credentials and key file name to the user_data dictionary
    user_data[encrypted_text.decode('utf-8')] = {'username': user_entry.get(), 'key_file': key_file_name}

    # save changes to the data.json file
    with open(os.path.join(sys.path[0], "data.json"), "w") as f:
        json.dump(user_data, f)

    messagebox.showinfo("Success", "Your account has been created successfully.")

# setup window
window = Tk()
window.title("Login Screen")
window.geometry("250x200")

# set up labels
Label(window, text = "Username").grid(row = 0, column = 0, padx = 10, pady = 10)
Label(window, text = "Password").grid(row = 1, column = 0, padx = 10, pady = 10)

# set up entries
user_entry = Entry(window)
pass_entry = Entry(window, show = "*")

user_entry.grid(row = 0, column = 1, padx = 10, pady = 10)
pass_entry.grid(row = 1, column = 1, padx = 10, pady = 10)

# set up button
Button(window, text = "Login", command = check_credentials).grid(row = 2, column = 0, padx = 10, pady = 10)

# set up create account button
Button(window, text = "Create Account", command = create_account).grid(row = 2, column = 1, padx = 10, pady = 10)

#setup quit button
Button(window, text="Quit", command=window.destroy).grid(row=3, column=0, padx=10, pady=10)

window.mainloop()