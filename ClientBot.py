import socket
import threading
import customtkinter as ctk
import json
import os
import subprocess
import sys
import re
import keyinput
import pyautogui
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timezone
from tkinter import filedialog
from tkinter.scrolledtext import ScrolledText

# Server configuration (matches server settings)
PORT = 65432

# File to save configuration data
CONFIG_FILE = "config.json"

# Initialize UI variables
cod_exe_path = None
ip_entry = None
console_text = None
is_host = None

# Function to load configuration from a file
def load_configuration():
    global cod_exe_path, ip_entry
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as file:
            config = json.load(file)
            cod_exe_path.set(config.get('cod_exe_path', ''))
            ip_entry.set(config.get('ip_address', ''))  # Set IP in ip_entry variable
    else:
        print("No configuration file found. Using default values.")

# Function to save configuration to a file
def save_configuration():
    config = {
        'cod_exe_path': cod_exe_path.get(),
        'ip_address': ip_entry.get()  # Get IP from ip_entry variable
    }
    with open(CONFIG_FILE, 'w') as file:
        json.dump(config, file, indent=4)
    print("Configuration saved successfully.")

# Modified function to select the cod.exe path from the GUI
def select_cod_exe():
    path = filedialog.askopenfilename(filetypes=[("Executable Files", "*.exe")])
    if path:
        cod_exe_path.set(path)
        save_configuration()  # Save to JSON file after selecting the file path
        log_to_console(f"Selected path: {path}")

def log_to_console(message):
    console_text.config(state='normal')
    console_text.insert('end', message + '\n')
    console_text.config(state='disabled')
    console_text.see('end')

def start_client(server_ip):
    # Connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((server_ip, PORT))
        log_to_console("Connected to server.")
        save_configuration()
        while True:
            # Receive command from server
            data = client_socket.recv(1024)
            if not data:
                break

            message = data.decode()
            log_to_console(f"Received command: {message}")

            match message:
                case "START_COD":
                    relaunch_game()

                case "STOP":
                    log_to_console("Stopping movements as per server instruction.")
                    break

                case "POINT_UP":
                    # Get the current position of the mouse
                    current_x, current_y = pyautogui.position()
                    new_y = current_y + 20
                    pyautogui.moveTo(current_x, new_y)
                    log_to_console(f"Moving Cursor - X: {current_x}, Y: {new_y}")

                case hex_pattern if re.match(r"^0x[0-9a-fA-F]+,\s*\d+$", hex_pattern):
                    match = re.match(r"(0x[0-9a-fA-F]+),\s*(\d+)", hex_pattern)
                    if match:
                        hex_code_str, duration = match.groups()
                        log_to_console(f"Hex code: {hex_code_str}, Duration: {duration}")
                        hex_code = int(hex_code_str, 16)  # Convert hex string to an integer
                        keyinput.holdKey(hex_code, int(duration))

                    else:
                        log_to_console("No match found.")

                # New pattern matching case for "1,3" style command
                case comma_separated if re.match(r"^\d+,\d+$", comma_separated):
                    x, y = map(int, comma_separated.split(","))
                    keyinput.click(x=x, y=y)
                    log_to_console(f"Parsed numbers - X: {x}, Y: {y}")

                case "START_MATCH":
                    if is_host.get():  # Check if designated as host
                        keyinput.toggleKey(keyinput.SPACE)
                        log_to_console("Starting Match")

                case _:
                    log_to_console("Not a valid entry")

def relaunch_game():
    try:
        subprocess.Popen([cod_exe_path.get()])
        log_to_console("Game relaunched successfully.")
    except Exception as e:
        log_to_console(f"Failed to launch the game: {e}")
        sys.exit(1)

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

def setup_ui():
    global cod_exe_path, console_text, ip_entry, is_host
    # Modern GUI setup using customtkinter
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    root = ctk.CTk()
    root.title("Pew's AFK Slave BOT")
    root.geometry("700x450")
    root.resizable(False, False)

    # Initialize UI variables as StringVar and BooleanVar
    cod_exe_path = ctk.StringVar()
    ip_entry = ctk.StringVar()
    is_host = ctk.BooleanVar(value=False)

    # Load the saved configuration when the script starts
    load_configuration()

    # COD.exe Path Entry
    ctk.CTkLabel(root, text="COD.exe Path:").grid(row=0, column=0, padx=10, pady=10)
    ctk.CTkButton(root, text="Select", command=select_cod_exe).grid(row=0, column=1, padx=10, pady=10)

    # IP Entry Field
    ctk.CTkLabel(root, text="Server IP Address:").grid(row=1, column=0, padx=10, pady=10)
    ip_entry_field = ctk.CTkEntry(root, textvariable=ip_entry, width=200)  # Bind to ip_entry
    ip_entry_field.grid(row=1, column=1, padx=10, pady=10)

    # Radio buttons for Host designation
    ctk.CTkLabel(root, text="Host Mode:").grid(row=2, column=0, padx=10, pady=10)
    host_radio = ctk.CTkRadioButton(root, text="Host", variable=is_host, value=True)
    non_host_radio = ctk.CTkRadioButton(root, text="Non-Host", variable=is_host, value=False)
    host_radio.grid(row=2, column=1, padx=10, pady=5, sticky="w")
    non_host_radio.grid(row=2, column=2, padx=10, pady=5, sticky="w")

    # Console for logging
    console_text = ScrolledText(root, wrap='word', height=10, state='disabled', bg="#2d2d2d", fg="white")
    console_text.grid(row=3, column=0, columnspan=3, padx=10, pady=10, sticky="we")

    # Start client in a separate thread
    start_button = ctk.CTkButton(root, text="Start Client", command=lambda: threading.Thread(target=start_client, args=(ip_entry.get(),)).start())
    start_button.grid(row=4, column=1, pady=10)

    root.mainloop()

# if validate_license():
setup_ui()