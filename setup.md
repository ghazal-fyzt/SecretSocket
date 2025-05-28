1git clone <this project>

2Create & activate a Python virtual environment
Create the venv:

python -m venv .venv

Activate it (PowerShell):

.\.venv\Scripts\Activate.ps1
3Install Python dependencies

Install core libs and tools:

pip install pynacl flask flask-socketio eventlet pytest pytest-benchmark black pre-commit
Enable pre-commit hooks for auto-formatting:
pre-commit install

| Purpose        | Command (Linux/macOS)                                | Notes                         |
| -------------- | ---------------------------------------------------- | ----------------------------- |
| Python runtime | `sudo apt install python3 python3-venv`              | ≥3.11 recommended             |
| Virtual env    | `python3 -m venv .venv && source .venv/bin/activate` | Keeps deps isolated           |
| Cryptography   | `pip install pynacl`                                 | Python bindings for libsodium |
| WebSockets     | `pip install flask flask-socketio eventlet`          | Real-time server              |
| Tooling        | `pip install pytest black pre-commit`                | Quality & tests               |





4Download & install Node.js from https://nodejs.org.

In the client/ folder, initialize and install Socket.IO client:

cd client

npm init -y

npm install socket.io-client

5Install Wireshark for packet capture demo

Download & install from https://wireshark.org.

Allow non-admin packet capture when prompted.
