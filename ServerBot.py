import socket
import threading
import time
import tkinter as tk
import json
from tkinter import scrolledtext
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timezone

# Server configuration
HOST = '0.0.0.0'  # Listen on all available interfaces
PORT = 65432
clients = []  # List to keep track of all connected clients
broadcasting = False  # Flag to control the broadcast loop


# Function to handle individual client connections
def handle_client(client_socket, address, log_widget):
    log_widget.insert(tk.END, f"[NEW CONNECTION] {address} connected.\n")
    clients.append(client_socket)  # Add client to the list

    try:
        while True:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break
            log_widget.insert(tk.END, f"[{address}] {message}\n")
    except Exception as e:
        log_widget.insert(tk.END, f"[ERROR] {e}\n")
    finally:
        log_widget.insert(tk.END, f"[DISCONNECT] {address} disconnected.\n")
        clients.remove(client_socket)
        client_socket.close()

# Function to broadcast messages to all connected clients
def broadcast(message, log_widget):
    for client in clients:
        try:
            client.send(message.encode('utf-8'))
            log_widget.insert(tk.END, f"[SERVER] Broadcasted: {message}\n")
        except Exception as e:
            log_widget.insert(tk.END, f"[ERROR] Failed to send message to client: {e}\n")
            clients.remove(client)
            client.close()

# Function to start the server and handle incoming connections
def start_server(log_widget):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    log_widget.insert(tk.END, f"[LISTENING] Server is listening on {HOST}:{PORT}\n")

    def accept_clients():
        while True:
            client_socket, address = server.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, address, log_widget))
            client_thread.start()

    threading.Thread(target=accept_clients, daemon=True).start()


# Function to continuously send commands
def start_broadcasting(log_widget):
    global broadcasting
    broadcasting = True

    # List of commands to broadcast
    commands = [
        "POINT_UP"
        "0,0"
        "0x11,2",
        "0x39,1",
        "0,0"
        "0x1F,2",
        "0x39,1",
        "0,0"
        "0x32,1"
    ]

    while broadcasting:
        for command in commands:
            if broadcasting:
                broadcast(command, log_widget)
                time.sleep(3)  # Delay between broadcasts


# Functions to send specific commands through the broadcast function
def send_start(log_widget):
    threading.Thread(target=start_broadcasting, args=(log_widget,), daemon=True).start()


def stop_sending(log_widget):
    global broadcasting
    broadcasting = False
    log_widget.insert(tk.END, f"[SERVER] Broadcast stopped\n")


def send_stop(log_widget):
    global broadcasting
    broadcasting = False
    broadcast("STOP", log_widget)


def send_start_match(log_widget):
    broadcast("START_MATCH", log_widget)


def send_start_cod(log_widget):
    broadcast("START_COD", log_widget)

def validate_license():
    try:
        # Load the public key
        with open("public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        # Load the license file (data and signature)
        with open("license.key", "rb") as f:
            license_content = f.read().split(b"\n")
            license_data_json = license_content[0]
            license_signature = license_content[1]

        # Verify the license signature
        public_key.verify(
            license_signature,
            license_data_json,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        # Check if license has expired
        license_data = json.loads(license_data_json)
        expiration_date = datetime.fromisoformat(license_data["expiration"])
        if expiration_date < datetime.now(timezone.utc):
            print("License has expired.")
            return False

        print("License is valid.")
        return True

    except InvalidSignature:
        print("Invalid license signature.")
        return False
    except Exception as e:
        print(f"License validation error: {e}")
        return False

# Setup the Tkinter UI for the server
def setup_ui():
    root = tk.Tk()
    root.title("Server Control Panel")
    root.geometry("400x300")

    # Buttons for sending commands
    start_button = tk.Button(root, text="Start", command=lambda: send_start(log_widget))
    start_button.pack(pady=5)

    stop_script_button = tk.Button(root, text="Stop Script", command=lambda: stop_sending(log_widget))
    stop_script_button.pack(pady=5)

    stop_button = tk.Button(root, text="Stop Completely", command=lambda: send_stop(log_widget))
    stop_button.pack(pady=5)


    start_cod__button = tk.Button(root, text="Start COD", command=lambda: send_start_cod(log_widget))
    start_cod__button.pack(pady=5)

    start_match_button = tk.Button(root, text="Start Match", command=lambda: send_start_match(log_widget))
    start_match_button.pack(pady=5)

    # Log display area
    log_widget = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=50, height=10)
    log_widget.pack(pady=10)
    log_widget.insert(tk.END, "[STARTING] Server is starting...\n")

    # Start the server in a separate thread
    threading.Thread(target=start_server, args=(log_widget,), daemon=True).start()

    root.mainloop()


if validate_license():
    # Start the server UI
    setup_ui()

