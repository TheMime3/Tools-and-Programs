import ssl
import socket
import os
import sys
import base64
import requests
from tkinter import *
from tkinter import messagebox
from threading import Thread

class ChatClientGUI:
    def __init__(self, master, ip_address, port, client_socket):
        self.master = master
        self.client_socket = client_socket
        self.client_list = []
        self.master.title("Chat Client")
        self.master.geometry("400x500")

        self.text_box = Text(master, height=20, width=50)
        self.text_box.pack()

        self.entry = Entry(master, width=50)
        self.entry.pack()
        self.entry.bind("<Return>", self.send_message)

        self.client_listbox = Listbox(master, height=5)
        self.client_listbox.pack()

    def connect(self, ip_address, port, client_socket):
        self.client_socket = client_socket

        try:
            # Connect to the specified server
            self.client_socket.connect((ip_address, port))
        except:
            self.text_box.insert('end', 'Error: Could not connect to the server')
            return False

        self.connected = True

        # Start a new thread to receive messages from the server
        receive_thread = Thread(target=self.receive_messages)
        receive_thread.start()
        return True
        
    def start_receive_thread(self):
        Thread(target=self.receive_messages).start()

    def send_message(self, event):
        message = self.entry.get()
        self.entry.delete(0, 'end')
        self.text_box.insert('end', f'You: {message}\n')
        self.text_box.see('end')
        self.client_socket.send(message.encode())

    def display_message(self, message):
        self.text_box.insert('end', message)
        self.text_box.see('end')

    def update_client_list(self, client_names):
        self.client_listbox.delete(0, 'end')
        for name in client_names:
            self.client_listbox.insert('end', name)

    def start(self):
        self.master.destroy()
        chat_window = Toplevel()
        chat_window.title("Chat Client")
        self.chat_transcript_area = Text(chat_window, width=60, height=20)
        self.enter_text_widget = Entry(chat_window, width=60)
        self.enter_text_widget.bind('<Return>', self.send)
        self.chat_transcript_area.grid(row=0, column=0, padx=10, pady=10)
        self.enter_text_widget.grid(row=1, column=0, padx=10, pady=10)
        self.enter_text_widget.focus()

    def send(self, event=None):
        message = self.enter_text_widget.get()
        self.enter_text_widget.delete(0, 'end')

        try:
            self.client_socket.sendall(message.encode('utf-8'))
        except:
            self.chat_transcript_area.insert('end', 'Error: Could not send message to the server')
            self.connected = False

    def receive_messages(self):
        while True:
            try:
                data = self.client_socket.recv(1024).decode()
            except:
                print("Connection closed")
                break
            if not data:
                print("Connection closed")
                break
            self.text_box.insert('end', f'{data}\n')
            self.text_box.see('end')

class ChatServerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Chat Server")
        self.master.geometry("400x500")

        self.text_box = Text(master, height=20, width=50)
        self.text_box.pack()

        self.entry = Entry(master, width=50)
        self.entry.pack()
        self.entry.bind("<Return>", self.send_message)

        self.client_listbox = Listbox(master, height=5)
        self.client_listbox.pack()

        self.start_server_button = Button(master, text="Start Server", command=self.start_server)
        self.start_server_button.pack(pady=5)

        self.quit_button = Button(master, text="Quit", command=self.master.quit)
        self.quit_button.pack()

    def start_server(self):
        # Create the server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Create SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        password = get_password()
        certfile = os.path.join(sys.path[0], 'cert.pem')
        keyfile = os.path.join(sys.path[0], 'key.pem')
        context.load_cert_chain(certfile, keyfile, password=password)

        # Wrap the server socket with SSL
        server_socket = context.wrap_socket(server_socket, server_side=True)

        # Bind the socket to the given address and port
        server_socket.bind((self.ip_address, self.port))

        # Listen for incoming connections
        server_socket.listen(5)

        self.text_box.insert('end', f'Listening for incoming connections on {self.ip_address}:{self.port}...\n')
        self.text_box.see('end')

        while True:
            client_socket, address = server_socket.accept()
            self.text_box.insert('end', f'Accepted connection from {address}\n')
            self.text_box.see('end')

            self.client_listbox.insert('end', address)

            Thread(target=self.receive_messages, args=(client_socket,)).start()

    def receive_messages(self, client_socket):
        while True:
            try:
                data = client_socket.recv(1024).decode()
            except:
                self.text_box.insert('end', f"Connection from {client_socket.getpeername()} closed\n")
                self.text_box.see('end')
                self.client_listbox.delete(self.client_listbox.get(0, 'end').index(client_socket.getpeername()))
                break
            if not data:
                self.text_box.insert('end', f"Connection from {client_socket.getpeername()} closed\n")
                self.text_box.see('end')
                self.client_listbox.delete(self.client_listbox.get(0, 'end').index(client_socket.getpeername()))
                break
            self.text_box.insert('end', f'{client_socket.getpeername()}: {data}')
            self.text_box.see('end')
            for client in self.client_list:
                if client != client_socket:
                    try:
                        client.send(data.encode())
                    except:
                        client.close()
                        self.client_list.remove(client)
        client_socket.close()

class IPDisplay:
    def __init__(self, master):
        self.master = master
        self.master.title("IP Display")
        self.master.geometry("300x100")

        self.internal_label = Label(self.master, text="Internal IP: ")
        self.internal_label.pack()
        
        self.external_label = Label(self.master, text="External IP: ")
        self.external_label.pack()

        self.show_ips_button = Button(self.master, text="Show IPs", command=self.show_ips)
        self.show_ips_button.pack(pady=5)

        self.quit_button = Button(self.master, text="Quit", command=self.master.quit)
        self.quit_button.pack()

    def show_ips(self):
        # Get internal IP address
        internal_ip = socket.gethostbyname(socket.gethostname())
        self.internal_label.config(text=f"Internal IP: {internal_ip}")
        
        # Get external IP address
        try:
            response = requests.get('https://api.ipify.org')
            external_ip = response.text
            self.external_label.config(text=f"External IP: {external_ip}")
        except:
            self.external_label.config(text="Failed to get external IP")

def get_password():
    f = "MTIzNDU="
    password = base64.b64decode(f).decode('utf-8')
    return password

def start_gui():
    root = Tk()
    root.geometry("600x400")
    root.title("Chat Program")

    # Server connection form
    connection_frame = Frame(root)
    connection_frame.pack(side=TOP)

    ip_label = Label(connection_frame, text="IP Address")
    ip_label.pack(side=LEFT)

    ip_entry = Entry(connection_frame)
    ip_entry.pack(side=LEFT)

    port_label = Label(connection_frame, text="Port")
    port_label.pack(side=LEFT)

    port_entry = Entry(connection_frame)
    port_entry.pack(side=LEFT)

    # Chat client frame
    client_frame = Frame(root)
    client_frame.pack(side=TOP)

    client_label = Label(client_frame, text="Chat Client")
    client_label.pack(side=TOP)

    # Create a socket instance
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect_to_server():
        ip_address = ip_entry.get()
        port_str = port_entry.get()

        if not port_str:
            messagebox.showerror("Error", "Please enter a port number")
            return

        try:
            port = int(port_str)
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
            return

        # Create a socket instance
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Create the SSL context
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_verify_locations((os.path.join(sys.path[0], 'cert.perm')))

        # Wrap the socket with SSL
        client_socket = context.wrap_socket(client_socket, server_hostname=ip_address)

        # Create the ChatClientGUI instance with the ip_address and port arguments
        client_chat = ChatClientGUI(client_frame, ip_address, port, client_socket)

        # Connect to the server
        connected = client_chat.connect()

        if connected:
            # Create a start client button
            start_client_btn = Button(client_frame, text='Start Client', command=client_chat.start)
            start_client_btn.pack(side=LEFT)
            start_client_btn.config(state=NORMAL)

            # Disable the connect to server button
            connect_btn.config(state=DISABLED)

            # Enable the show ips button
            show_ips_btn.config(state=NORMAL)



    connect_btn = Button(connection_frame, text='Connect', command=connect_to_server)
    connect_btn.pack(side=LEFT)

    # Create a start client button
    start_client_btn = Button(client_frame, text='Start Client', command=lambda: ChatClientGUI.start())
    start_client_btn.pack(side=LEFT)
    start_client_btn.config(state=DISABLED)

    # Create a show IPs button
    ip_display = None
    def show_ips():
        nonlocal ip_display
        if ip_display is None:
            ip_display = IPDisplay(Toplevel(root))
        else:
            ip_display.master.deiconify()

    show_ips_btn = Button(root, text="Show IPs", command=show_ips)
    show_ips_btn.pack(row=3, column=0, columnspan=2, padx=2, pady=2)

    # Create a quit button
    quit_btn = Button(root, text='Quit', command=root.quit)
    quit_btn.pack(row=4, column=0, columnspan=2, padx=2, pady=2)

    # Run the mainloop
    root.mainloop()
