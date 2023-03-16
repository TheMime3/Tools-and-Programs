import socket
import requests
import tkinter as tk
from tkinter import ttk
from concurrent.futures import ThreadPoolExecutor
import threading

def check_port(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect(('localhost', port))
        s.close()
        return True
    except socket.error:
        return False


def scan_ports(start_port, end_port, progress_callback=None):
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(check_port, port) for port in range(start_port, end_port + 1)]
        for i, future in enumerate(futures):
            result = future.result()
            if result:
                open_ports.append(i + start_port)
            if progress_callback:
                progress_callback(i + 1, len(futures))

    return open_ports

def check_port_forwarding(port):
    url = "https://ports.yougetsignal.com/check-port.php"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    }
    data = {
        "remoteAddress": requests.get("https://api.ipify.org").text,
        "portNumber": port,
    }
    try:
        response = requests.post(url, headers=headers, data=data).json()

        if response["status"] == "Success":
            return response["portStatus"] == "open"
        else:
            print("Error checking port forwarding:", response["error"])
            return False
    except requests.exceptions.JSONDecodeError:
        print("Error decoding JSON response from the server.")
        return False

def start_scan():
    scan_button.config(state="disabled")
    status_label.config(text="Scanning...")
    progress_bar["value"] = 0
    threading.Thread(target=perform_scan, daemon=True).start()

def perform_scan():
    start_port = int(start_port_entry.get())
    end_port = int(end_port_entry.get())
    open_ports = scan_ports(start_port, end_port, update_progress_bar)
    result_text.delete(1.0, tk.END)

    if open_ports:
        result_text.insert(tk.END, f"Open ports: {open_ports}\n")
        for port in open_ports:
            if check_port_forwarding(port):
                result_text.insert(tk.END, f"Port {port} is forwarded\n")
            else:
                result_text.insert(tk.END, f"Port {port} is not forwarded\n")
    else:
        result_text.insert(tk.END, "No open ports found")

    status_label.config(text="Scan complete")
    scan_button.config(state="normal")

def update_progress_bar(current, total):
    progress_bar["value"] = (current / total) * 100
    app.update_idletasks()

if __name__ == "__main__":
    app = tk.Tk()
    app.title("Port Scanner")

    start_port_label = ttk.Label(app, text="Start Port:")
    start_port_label.grid(column=0, row=0, padx=(10, 5), pady=10, sticky="W")
    start_port_entry = ttk.Entry(app, width=10)
    start_port_entry.grid(column=1, row=0, padx=(5, 10), pady=10, sticky="W")

    end_port_label = ttk.Label(app, text="End Port:")
    end_port_label.grid(column=0, row=1, padx=(10, 5), pady=10, sticky="W")
    end_port_entry = ttk.Entry(app, width=10)
    end_port_entry.grid(column=1, row=1, padx=(5, 10), pady=10, sticky="W")

    scan_button = ttk.Button(app, text="Start Scan", command=start_scan)
    scan_button.grid(column=0, row=2, padx=10, pady=10, columnspan=2)

    result_label = ttk.Label(app, text="Results:")
    result_label.grid(column=0, row=3, padx=10, pady=(0, 10), sticky="W")

    result_text = tk.Text(app, wrap=tk.WORD, width=40, height=10)
    result_text.grid(column=0, row=4, padx=10, pady=(0, 10), columnspan=2)

    scrollbar = ttk.Scrollbar(app, orient="vertical", command=result_text.yview)
    scrollbar.grid(column=2, row=4, padx=(0, 10), pady=(0, 10), sticky="ns")
    result_text.config(yscrollcommand=scrollbar.set)

    status_label = ttk.Label(app, text="")
    status_label.grid(column=0, row=5, padx=10, pady=(0, 10), sticky="W", columnspan=2)

    progress_bar = ttk.Progressbar(app, orient="horizontal", length=250, mode="determinate")
    progress_bar.grid(column=0, row=6, padx=10, pady=(0, 10), sticky="W", columnspan=2)

    app.mainloop()

