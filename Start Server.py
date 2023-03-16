import sys
import subprocess

def check_and_prompt_package(package_name):
    try:
        __import__(package_name)
    except ImportError:
        print(f"The required package '{package_name}' is not installed.")
        while True:
            answer = input(f"Do you want to install '{package_name}' now? (y/n): ").strip().lower()
            if answer == 'y':
                subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
                break
            elif answer == 'n':
                print(f"Please install the '{package_name}' package manually and restart the script.")
                sys.exit(1)

check_and_prompt_package("requests")
check_and_prompt_package("pycryptodomex")

import socket
import threading
import requests
import base64
from datetime import datetime
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import tkinter as tk
from tkinter import scrolledtext

# Encryption functions
def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def encrypt(plaintext, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(pad(plaintext).encode()))

# Server connection function
def start_server(port, message_history):
    def handle_client(client_socket, client_address, key):
        while True:
            try:
                msg_length = client_socket.recv(HEADER).decode(FORMAT)
                if msg_length:
                    msg_length = int(msg_length)
                    msg = client_socket.recv(msg_length).decode(FORMAT)
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    encrypted_msg = encrypt(f"{timestamp} {msg}", key)
                    broadcast(encrypted_msg)
                    message_history.configure(state=tk.NORMAL)
                    message_history.insert(tk.END, f"{timestamp} {client_address[0]}: {msg}\n")
                    message_history.configure(state=tk.DISABLED)

            except Exception as e:
                print(f"Error: {e}")
                client_socket.close()
                clients.remove(client_socket)
                break

    def broadcast(msg):
        for client in clients:
            client.send(msg)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('', port))
    server.listen()
    server.settimeout(1)  # Set a timeout of 1 second for the server socket

    try:
        ip_address = requests.get('https://api.ipify.org').text
    except requests.exceptions.RequestException:
        ip_address = "unknown"


    message_history.configure(state=tk.NORMAL)
    message_history.insert(tk.END, f"Server started on {ip_address} and port {port}\n")
    message_history.configure(state=tk.DISABLED)

    key = get_random_bytes(32)

    try:
        while not stop_server_flag.is_set():
            try:
                client_socket, client_address = server.accept()
            except socket.timeout:
                continue

            clients.append(client_socket)
            print(f"New connection from {client_address}")
            thread = threading.Thread(target=handle_client, args=(client_socket, client_address, key))
            thread.start()
            print(f"Active connections: {threading.active_count() - 1}")

    except KeyboardInterrupt:
        print("\nShutting down the server.")
        server.close()

    server.close()
    message_history.configure(state=tk.NORMAL)
    message_history.insert(tk.END, f"Server stopped.\n")
    message_history.configure(state=tk.DISABLED)

    key = get_random_bytes(32)

    try:
        while not stop_server_flag.is_set():
            client_socket, client_address = server.accept()
            clients.append(client_socket)
            print(f"New connection from {client_address}")
            thread = threading.Thread(target=handle_client, args=(client_socket, client_address, key))
            thread.start()
            print(f"Active connections: {threading.active_count() - 1}")

    except KeyboardInterrupt:
        print("\nShutting down the server.")
        server.close()

    server.close()
    message_history.configure(state=tk.NORMAL)
    message_history.insert(tk.END, f"Server stopped.\n")
    message_history.configure(state=tk.DISABLED)

def start_server_gui(port, message_history):
    def run_server():
        start_server(int(port), message_history)

    server_thread = threading.Thread(target=run_server)
    server_thread.start()

# Global variables
HEADER = 64
FORMAT = "utf-8"
clients = []
stop_server_flag = threading.Event()

# Create the server login window
server_login_window = tk.Tk()
server_login_window.title("Server Login")

port_label = tk.Label(server_login_window, text="Port:")
port_entry = tk.Entry(server_login_window)

message_history_frame = tk.Frame(server_login_window)
message_history = scrolledtext.ScrolledText(message_history_frame, wrap=tk.WORD, width=60, height=20, state=tk.DISABLED)
message_history.grid(sticky="nsew")
message_history_frame.grid(sticky="nsew", padx=5, pady=5)
message_history_frame.grid(sticky="nsew", padx=5, pady=5)

start_server_button = tk.Button(server_login_window, text="Start Server", command=lambda: [start_server_gui(port_entry.get(), message_history), stop_server_button.config(state=tk.NORMAL), start_server_button.config(state=tk.DISABLED)])
stop_server_button = tk.Button(server_login_window, text="Stop Server", state=tk.DISABLED, command=lambda: [stop_server_flag.set(), start_server_button.config(state=tk.NORMAL), stop_server_button.config(state=tk.DISABLED)])

port_label.grid(row=0, column=0, sticky="e")
port_entry.grid(row=0, column=1)

start_server_button.grid(row=1, column=1, pady=10)
stop_server_button.grid(row=1, column=0, pady=10)

server_login_window.columnconfigure(0, weight=1)
server_login_window.rowconfigure(1, weight=1)

server_login_window.mainloop()


