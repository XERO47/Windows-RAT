# ============================================================================
# RAT CLEANUP SCRIPT
# Author: Gemini
#
# This script removes the persistence mechanisms created by the RAT.
# It is essential for cleaning a test environment between experiments.
#
# USAGE:
# 1. Open PowerShell or Command Prompt AS ADMINISTRATOR.
# 2. Navigate to the directory containing this script.
# 3. Run the script: `python cleanup_rat.py`
#
# WHAT IT DOES:
# - Deletes the scheduled task used for high-privilege persistence.
# - Deletes the registry key used as a "first run" flag.
#
# NOTE: You must run this with administrator rights for it to work.
# ============================================================================

import ctypes
import os
import sys
import subprocess
import winreg as reg

# --- Configuration ---
# This MUST match the PERSISTENCE_NAME variable in your client script.
PERSISTENCE_NAME = "SystemStabilityService"

def is_admin():
    """ Checks for administrator privileges. """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def delete_scheduled_task():
    """
    Forcefully deletes the scheduled task created by the RAT.
    This requires administrator privileges.
    """
    print(f"[*] Attempting to delete Scheduled Task: '{PERSISTENCE_NAME}'...")
    try:
        # The command to delete the scheduled task. /f forces deletion.
        command = f'schtasks /delete /tn "{PERSISTENCE_NAME}" /f'
        
        # We run the command and capture output to check for success.
        # `check=True` will raise an exception if the command fails.
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        
        if "SUCCESS" in result.stdout:
            print(f"[+] SUCCESS: Scheduled Task '{PERSISTENCE_NAME}' was deleted.")
        # Some versions might not print SUCCESS but still work if no error is raised
        elif result.returncode == 0:
            print(f"[+] SUCCESS: Scheduled Task '{PERSISTENCE_NAME}' was deleted (command executed successfully).")

    except subprocess.CalledProcessError as e:
        # This error typically means the task did not exist.
        if "ERROR: The specified task name" in e.stderr:
            print(f"[-] INFO: The scheduled task '{PERSISTENCE_NAME}' does not exist. Nothing to delete.")
        else:
            print(f"[!] ERROR: Failed to delete scheduled task. Maybe it doesn't exist or there was a permissions issue.")
            print(f"   Stderr: {e.stderr.strip()}")
    except Exception as e:
        print(f"[!] An unexpected error occurred while deleting the task: {e}")

def delete_registry_flag():
    """
    Deletes the registry key used by the RAT to check if it has run before.
    """
    print(f"[*] Attempting to delete Registry Flag: 'HKCU\\Software\\{PERSISTENCE_NAME}'...")
    try:
        # Open the parent key (HKEY_CURRENT_USER\Software) with write access
        parent_key = reg.OpenKey(reg.HKEY_CURRENT_USER, r"Software", 0, reg.KEY_WRITE)
        
        # Delete the specific key (our flag)
        reg.DeleteKey(parent_key, PERSISTENCE_NAME)
        
        # Close the parent key
        reg.CloseKey(parent_key)
        
        print(f"[+] SUCCESS: Registry key '{PERSISTENCE_NAME}' was deleted.")
    except FileNotFoundError:
        print(f"[-] INFO: The registry key '{PERSISTENCE_NAME}' does not exist. Nothing to delete.")
    except Exception as e:
        print(f"[!] ERROR: An unexpected error occurred while deleting the registry key: {e}")


if __name__ == '__main__':
    print("--- RAT Persistence Cleanup Utility ---")

    # 1. Check for admin rights before proceeding.
    # if not is_admin():
    #     print("\n[!] ERROR: This script requires administrator privileges to run.")
    #     print("    Please re-run it from a PowerShell or Command Prompt opened as Administrator.")
    #     sys.exit(1)

    print("\n[+] Running with administrator privileges.")
    
    # 2. Call the cleanup functions.
    delete_scheduled_task()
    delete_registry_flag()

    print("\n--- Cleanup process complete. ---")