"""
Interactive WebSocket client for SecretSocket with:
- Ephemeral key handshake
- Message encryption/decryption
- Perfect Forward Secrecy via key rotation
- User input loop for sending messages
"""

import sys
import threading
from nacl.public import PublicKey
import socketio
from client.crypto import (
    generate_ephemeral_keypair,
    derive_session_key,
    encrypt_message,
    decrypt_message,
)

# Rotate keys after this many messages
ROTATION_THRESHOLD = 20

class SecretSocketClient:
    def __init__(self, server_url, peer_static_pub_hex=None):
        self.sio = socketio.Client()
        self.server_url = server_url
        self.eph_priv = None
        self.eph_pub = None
        self.session_key = None
        self.msg_count = 0

        # (Optional) static peer key
        self.peer_static_pub = (
            PublicKey(bytes.fromhex(peer_static_pub_hex))
            if peer_static_pub_hex else None
        )

        # Register event handlers
        self.sio.on('connect', self.on_connect)
        self.sio.on('handshake', self.on_handshake)
        self.sio.on('msg', self.on_message)

    def start(self):
        """Connect to server and begin user input loop."""
        # Connect to the Socket.IO server
        self.sio.connect(self.server_url)
        # Start a background thread to read user input
        threading.Thread(target=self._input_loop, daemon=True).start()
        # Keep main thread alive
        threading.Event().wait()

    def _input_loop(self):
        """Continuously read from stdin and send user messages."""
        while True:
            try:
                text = input()
            except EOFError:
                break
            if not text.strip():
                continue
            self.send_chat(text.strip())

    def on_connect(self):
        """Generate ephemeral keys and initiate handshake on connect."""
        self.eph_priv, self.eph_pub = generate_ephemeral_keypair()
        self.sio.emit('handshake', {'public_key': self.eph_pub.encode().hex()})

    def on_handshake(self, data):
        """Receive peer's public key, derive session key, reset counter."""
        peer_pub = PublicKey(bytes.fromhex(data['public_key']))
        self.session_key = derive_session_key(self.eph_priv, peer_pub)
        print('[*] Session established. You can start chatting.')
        self.msg_count = 0

    def send_chat(self, text):
        """Encrypt and emit a chat message."""
        if not self.session_key:
            print('[-] No session key yet. Please wait for handshake.')
            return
        ciphertext = encrypt_message(self.session_key, text.encode())
        self.sio.emit('msg', {'body': ciphertext.hex()})
        self._after_message()

    def on_message(self, data):
        """Receive and decrypt incoming chat messages."""
        if not self.session_key:
            return
        ciphertext = bytes.fromhex(data['body'])
        plaintext = decrypt_message(self.session_key, ciphertext)
        print(f'Peer: {plaintext.decode()}')
        self._after_message()

    def _after_message(self):
        """Increment counter and rotate keys if threshold reached."""
        self.msg_count += 1
        if self.msg_count >= ROTATION_THRESHOLD:
            print('[*] Rotating keys for PFS...')
            self.rotate_keys()

    def rotate_keys(self):
        """Wipe old key, generate new ephemeral pair, and handshake again."""
        self.session_key = None
        self.eph_priv, self.eph_pub = generate_ephemeral_keypair()
        self.sio.emit('handshake', {'public_key': self.eph_pub.encode().hex()})

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python client/app.py <server_url> [peer_static_pub_hex]')
        sys.exit(1)
    server = sys.argv[1]
    peer_hex = sys.argv[2] if len(sys.argv) >= 3 else None
    client = SecretSocketClient(server, peer_hex)
    client.start()
