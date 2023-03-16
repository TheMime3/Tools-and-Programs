import subprocess
import sys

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

packages = [("paramiko", "paramiko"), ("pycryptodome", "Cryptodome")]

for package_name, import_name in packages:
    try:
        __import__(import_name)
    except ImportError:
        while True:
            user_input = input(f"{package_name} is not installed. Do you want to install it now? (y/n): ")
            if user_input.lower() in ('y', 'yes'):
                install(package_name)
                __import__(import_name)
                break
            elif user_input.lower() in ('n', 'no'):
                sys.exit(f"Error: {package_name} is required to run this script. Exiting...")
            else:
                print("Invalid input. Please enter 'y' or 'n'.")

import base64
import tkinter as tk
from tkinter import messagebox, scrolledtext

import paramiko
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

# Encryption functions


def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)


def encrypt(plaintext, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(pad(plaintext).encode()))


def unpad(s):
    return s[:-ord(s[len(s) - 1:])]


def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext[AES.block_size:]).decode())

# SSH connection function


def ssh_connect(host, port, username):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port, username=username)
        client.get_username = lambda: username
        return client
    except Exception as e:
        return None


def send_message(client, message, key, recipient):
    encrypted_message = encrypt(message, key)
    _, stdout, _ = client.exec_command(
        f"echo '{encrypted_message.decode()}' >> messages_{recipient}.txt")
    stdout.channel.recv_exit_status()


def read_messages(client, key):
    _, stdout, _ = client.exec_command(
        f"cat messages_{client.get_username()}.txt")
    encrypted_messages = stdout.readlines()
    decrypted_messages = [decrypt(base64.b64decode(
        em.strip()), key) for em in encrypted_messages]
    return decrypted_messages

# Login button callback


def on_login():
    host = host_entry.get()
    port = int(port_entry.get())
    username = username_entry.get()

    client = ssh_connect(host, port, username)

    if client:
        login_window.destroy()
        create_messenger_window(client)
    else:
        messagebox.showerror(
            "Error", "Failed to connect. Please check your host and port and try again.")

# Send button callback


def on_send(client, key, message_entry, message_history, recipient):
    message = message_entry.get()
    message_history.configure(state=tk.NORMAL)
    message_history.insert(tk.END, f"You: {message}\n")
    message_history.configure(state=tk.DISABLED)
    message_entry.delete(0, tk.END)

    send_message(client, message, key, recipient)


def on_refresh(client, key, message_history):
    message_history.configure(state=tk.NORMAL)
    messages = read_messages(client, key)
    message_history.delete(1.0, tk.END)
    for message in messages:
        message_history.insert(tk.END, f"{message}\n")
    message_history.configure(state=tk.DISABLED)


def create_messenger_window(client):
    key = get_random_bytes(32)

    messenger_window = tk.Tk()
    messenger_window.title("SSH Messenger")

    message_history_frame = tk.Frame(messenger_window)
    message_history = scrolledtext.ScrolledText(
        message_history_frame, wrap=tk.WORD, width=60, height=20, state=tk.DISABLED)
    message_history.pack(expand=True, fill=tk.BOTH)
    message_history_frame.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)

    message_input_frame = tk.Frame(messenger_window)
    message_entry = tk.Entry(message_input_frame, width=50)
    message_entry.pack(side=tk.LEFT, padx=5, pady=5)
    send_button = tk.Button(message_input_frame, text="Send", command=lambda: on_send(
        client, key, message_entry, message_history, recipient_entry.get()))
    send_button.pack(side=tk.LEFT, padx=5, pady=5)

    recipient_label = tk.Label(message_input_frame, text="Recipient:")
    recipient_entry = tk.Entry(message_input_frame, width=20)
    recipient_label.pack(side=tk.LEFT, padx=(50, 0), pady=5)
    recipient_entry.pack(side=tk.LEFT, padx=5, pady=5)

    refresh_button = tk.Button(message_input_frame, text="Refresh",
                               command=lambda: on_refresh(client, key, message_history))
    refresh_button.pack(side=tk.LEFT, padx=5, pady=5)

    message_input_frame.pack(fill=tk.X)

    messenger_window.protocol("WM_DELETE_WINDOW", client.close)
    messenger_window.mainloop()


# Create the login window
login_window = tk.Tk()
login_window.title("SSH Login")

host_label = tk.Label(login_window, text="Host:")
host_entry = tk.Entry(login_window)

port_label = tk.Label(login_window, text="Port:")
port_entry = tk.Entry(login_window)

username_label = tk.Label(login_window, text="Username:")
username_entry = tk.Entry(login_window)

login_button = tk.Button(login_window, text="Login", command=on_login)

host_label.grid(row=0, column=0, sticky="e")
host_entry.grid(row=0, column=1)

port_label.grid(row=1, column=0, sticky="e")
port_entry.grid(row=1, column=1)

username_label.grid(row=2, column=0, sticky="e")
username_entry.grid(row=2, column=1)

login_button.grid(row=3, column=1, pady=10)

login_window.mainloop()
