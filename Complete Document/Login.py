from tkinter import *
import json
import os
import pandas
import csv
from cryptography.fernet import Fernet

# update check credentials function
def check_credentials():
    # setup encryption
    userPass = user_entry.get() + ':' + pass_entry.get()
    userPass = userPass.encode('utf-8')
    secret_key = Fernet.generate_key() # generate a key
    cipher = Fernet(secret_key)
    encrypted_text = cipher.encrypt(userPass)
   
    '''with open(r'./data.json') as f:'''
    '''user_data = json.load(f)'''

    # open json file
    user_data = pandas.read_csv(r".\data.csv")
    # check credentials

    if user_data.get(encrypted_text):
        print('Login Successful')
        window.destroy() # close login UI

        # open new UI
        success_window = Tk()
        success_window.title("Successful")
        success_window.geometry("800x400")

        # set success button
        Button(success_window, text="Success!", command=success_window.destroy).grid(row=0, column=0, padx=10, pady=10)

        success_window.mainloop()
    else:
        print('Login Failed')

# function to create account
def create_account():

    # set up encryption
    userPass = user_entry.get() + ':' + pass_entry.get()
    userPass = userPass.encode('utf-8')
    secret_key = Fernet.generate_key() # generate a key
    cipher = Fernet(secret_key)
    encrypted_text = cipher.encrypt(userPass)

    # open json file
    with open(r'./data.json') as f:
        user_data = json.load(f)

    # add credentials to json file
    user_data[encrypted_text] = user_entry.get()

    # save changes to json file
    with open(r'./data.json') as f:
        json.dump(user_data, f)

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