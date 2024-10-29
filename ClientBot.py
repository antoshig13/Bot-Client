import socket
import threading
import time
import customtkinter as ctk
from tkinter import filedialog, Text
from tkinter.scrolledtext import ScrolledText
import json
import os
import subprocess
import sys
import re

import keyinput

# Server configuration (matches server settings)
SERVER_IP = 'egpewpew.duckdns.org'
PORT = 65432

# File to save configuration data
CONFIG_FILE = "config.json"

is_host = False

# Function to load configuration from a file
def load_configuration():
    global cod_exe_path
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as file:
            config = json.load(file)
            cod_exe_path.set(config.get('cod_exe_path', ''))
    else:
        print("No configuration file found. Using default values.")

# Function to save configuration to a file
def save_configuration():
    global cod_exe_path
    config = {
        'cod_exe_path': cod_exe_path.get()
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

def start_client():
    # Connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((SERVER_IP, PORT))
        print("Connected to server.")

        while True:
            # Receive command from server
            data = client_socket.recv(1024)
            if not data:
                break

            message = data.decode()
            print(f"Received command: {message}")

            match message:
                case "START_COD":
                    relaunch_game()

                case "STOP":
                    log_to_console("Stopping movements as per server instruction.")
                    break

                case hex_pattern if re.match(r"^0x[0-9a-fA-F]+,\s*\d+$", hex_pattern):
                    match = re.match(r"(0x[0-9a-fA-F]+),\s*(\d+)", hex_pattern)
                    if match:
                        hex_code_str, duration = match.groups()
                        log_to_console(f"Hex code: {hex_code_str}, Duration: {duration}")
                        hex_code = int(hex_code_str, 16)  # Convert hex string to an integer
                        keyinput.holdKey(hex_code, int(duration))
                    else:
                        log_to_console("No match found.")

                case "START_MATCH":
                    if is_host.get():  # Check if designated as host
                        keyinput.toggleKey(keyinput.SPACE)
                        log_to_console("Starting Match")

                case _:
                    log_to_console("Not a valid entry")


def relaunch_game():
    try:
        subprocess.Popen([cod_exe_path.get()])
        # perform_post_launch_actions()
        log_to_console("Game relaunched successfully.")
    except Exception as e:
        log_to_console(f"Failed to launch the game: {e}")
        sys.exit(1)

def perform_post_launch_actions():
    pass

# Modern GUI setup using customtkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

root = ctk.CTk()
root.title("Pew's AFK Slave BOT")
root.geometry("700x450")
root.resizable(False, False)

# UI Elements setup
cod_exe_path = ctk.StringVar()

# Load the saved configuration when the script starts
load_configuration()

ctk.CTkLabel(root, text="COD.exe Path:").grid(row=0, column=0, padx=10, pady=10)
ctk.CTkButton(root, text="Select", command=select_cod_exe).grid(row=0, column=1, padx=10, pady=10)

# Radio buttons for Host designation
ctk.CTkLabel(root, text="Host Mode:").grid(row=1, column=0, padx=10, pady=10)
is_host = ctk.BooleanVar(value=False)
host_radio = ctk.CTkRadioButton(root, text="Host", variable=is_host, value=True)
non_host_radio = ctk.CTkRadioButton(root, text="Non-Host", variable=is_host, value=False)
host_radio.grid(row=1, column=1, padx=10, pady=5)
non_host_radio.grid(row=1, column=2, padx=10, pady=5)

# Console for logging
console_text = ScrolledText(root, wrap='word', height=10, state='disabled', bg="#2d2d2d", fg="white")
console_text.grid(row=5, column=0, columnspan=3, padx=10, pady=10, sticky="we")

# Start client in a separate thread
threading.Thread(target=start_client).start()

root.mainloop()