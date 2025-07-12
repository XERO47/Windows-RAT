
# Project: Python RAT - A Custom Remote Access Tool for Windows

**Author:** [Abhishek / xero47]  
**Status:** Educational / Proof of Concept

## ⚠️ Disclaimer

This project was undertaken strictly for **educational and research purposes**. The goal was to deepen my understanding of Python programming, Windows internals, networking, and modern cybersecurity principles (both offensive tradecraft and defensive strategies).

The software developed here is a functional Remote Access Tool (RAT).
## Overview

This project is my attempt at building a custom Remote Access Tool for Windows from the ground up using Python. My objective was to move beyond simple scripts and tackle a project that encompasses a wide range of real-world cybersecurity challenges. I wanted to build not just the tool itself, but to understand the "cat-and-mouse" game between an implant and system defenses.

The result is a sophisticated, multi-stage implant with a corresponding Command & Control (C2) server. The design mimics the architecture of modern malware, prioritizing stealth, persistence, and functionality.

## Core Features

The RAT is comprised of two main components: the **Client (Implant)** and the **Server (C2)**.

### Client-Side Implant (`rat_client_final.py`)

The client is a standalone Windows executable (compiled from Python) designed to be the primary implant on a target machine. It features a state-based design to maximize stealth.

*   **Multi-Stage Persistence:**
    1.  **UAC Self-Elevation:** On its first execution, the implant checks for administrator privileges. If not present, it uses the `runas` verb via the Windows API to trigger a UAC prompt, requesting elevation from the user.
    2.  **Relocation & Hiding:** Upon gaining admin rights, it copies itself from its initial location to a hidden, masqueraded path in `%APPDATA%` (e.g., `...\AppData\Roaming\NvidiaDisplayService\NvidiaDisplayService.exe`).
    3.  **High-Privilege Persistence:** It creates a Windows Scheduled Task configured to run the relocated executable as `NT AUTHORITY\SYSTEM` every time a user logs on. This provides silent, high-privilege execution on subsequent reboots without needing further UAC prompts.
    4.  **Anti-Forensics:** After successfully setting up persistence, the initial "dropper" executable schedules its own deletion using a detached batch script to clean up the entry point.

*   **State-Based Command & Control:**
    *   **Dormant State:** The implant's default state. It silently pings a hardcoded, legitimate-looking "dead drop" URL (e.g., a raw text file on GitHub) at long, randomized intervals (jitter). This "low-and-slow" beaconing is designed to blend in with normal network noise.
    *   **Active State:** When the content of the dead drop URL is changed to a valid C2 server address, the implant transitions to an active state. It then begins rapidly polling the C2 server for tasks, creating a responsive, interactive session.
    *   **Failover Logic:** If the active C2 server goes offline (detected by consecutive connection failures), the implant automatically reverts to its dormant state, resuming its slow pings to the dead drop URL to await new instructions.

*   **Core Capabilities:**
    *   **Remote Shell:** Execute arbitrary shell commands and receive the output.
    *   **File Upload:** Upload files from the C2 server to the victim machine. Essential for deploying second-stage tools like privilege escalation exploits or scanners.
    *   **File Download (Exfiltration):** Download arbitrary files from the victim machine to the C2 server.
    *   **Encrypted Communication:** All communication with the C2 server (shell output, file chunks) is encrypted using a simple XOR cipher and then Base64 encoded to ensure safe transport over HTTP.

### Server-Side Command & Control (`rat_server_http.py`)

The C2 server is a Python Flask application that provides the attacker's user interface and the necessary web endpoints for the implant to communicate with.

*   **Interactive Shell:** Provides a clean, responsive command-line interface for the attacker to issue commands and view results in real-time when a client is in its "Active State".
*   **Dynamic Tasking:** The C2 interface allows the attacker to queue up shell commands, file uploads, or file downloads.
*   **File Transfer Management:**
    *   Handles staging local files for upload to the victim.
    *   Manages incoming file transfers from the victim, reassembling encrypted chunks and saving the final file to a `downloads` directory.
*   **Stealthy Endpoints:** Uses generic-looking API endpoints (`/get_command`, `/send_results`, `/get_chunk`, etc.) to handle C2 communication.

## How it Works: The Attack Lifecycle

1.  **Initial Access:** An attacker delivers the compiled `rat_client.exe` to the target (e.g., via a phishing email, a dropper, or physical access like a BadUSB).
2.  **Execution & Persistence:** The user runs the executable. It prompts for UAC, gains admin rights, relocates itself, sets up the SYSTEM-level scheduled task, and deletes the original file.
3.  **Dormant Phase:** The RAT is now persistent. On every reboot, it runs silently as SYSTEM and begins pinging the dead drop URL, waiting for a command.
4.  **Activation:** The attacker wishes to take control. They start their `rat_server.py` and a forwarding service (like a Dev Tunnel or a VPS redirector) to get a public URL. They place this URL into the dead drop file.
5.  **Active C2 Session:** The client fetches the URL, connects to the C2 server, and enters a fast-polling active state. The attacker now has a fully interactive shell and file transfer capabilities.
6.  **Going Dark:** The attacker finishes their session and shuts down their C2 server. The client detects the connection loss and reverts to the dormant, low-profile state.

## Personal Learnings & Future Improvements

This project was an incredible learning experience. Key takeaways include:

*   **The Importance of Layers:** A simple reverse shell is easy to detect. Real-world effectiveness comes from layering techniques: persistence, UAC bypass, relocation, state-based C2, and encryption.
*   **Thinking Defensively:** At every step, I had to consider how a Blue Team would detect my tool. This forced me to implement features like jitter, masquerading, and anti-forensics.
*   **Windows Internals:** Gaining a practical understanding of Scheduled Tasks, the Registry, and the Windows API (`ctypes`) was invaluable.

**Potential future improvements could include:**

*   **Process Injection:** Implementing the ability to inject the RAT's shellcode into a legitimate process (e.g., `explorer.exe`) to hide from basic process list analysis.
*   **In-Memory Execution:** Modifying the client to download and execute second-stage tools entirely in memory without ever writing them to disk.
*   **More Robust Encryption:** Replacing the simple XOR cipher with a standard, strong cryptographic protocol like TLS, implemented directly or through a library like PyOpenSSL.
*   **Domain Fronting:** Evolving the dead drop mechanism to use a more advanced technique like domain fronting for even greater network stealth.
