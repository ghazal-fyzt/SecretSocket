"""
Interactive WebSocket client for SecretSocket with:
- Ephemeral key handshake (re-sent for late joiners)
- Message encryption/decryption
- Perfect Forward Secrecy via key rotation
- User input loop
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
    def __init__(self, server_url):
        """
        Initialize client, register Socket.IO handlers.
        """
        self.server_url = server_url
        self.sio = socketio.Client()
        self.eph_priv = None
        self.eph_pub = None
        self.session_key = None
        self.msg_count = 0

        # Register event handlers
        self.sio.on('connect', self.on_connect)
        self.sio.on('handshake', self.on_handshake)
        self.sio.on('msg', self.on_message)

    def start(self):
        """
        Connect to server and start input loop.
        """
        self.sio.connect(self.server_url)
        threading.Thread(target=self._input_loop, daemon=True).start()
        threading.Event().wait()

    def _input_loop(self):
        """
        Read console input and send messages.
        """
        while True:
            try:
                text = input()
            except EOFError:
                break
            if text.strip():
                self.send_chat(text.strip())

    def on_connect(self):
        """
        On connect: generate ephemeral keypair and send handshake twice.
        The second send (after delay) ensures late-joining peers receive it.
        """
        self.eph_priv, self.eph_pub = generate_ephemeral_keypair()
        self._send_handshake()

    def _send_handshake(self):
        """
        Emit handshake now and a second time after 1 second for late joiners.
        """
        data = {'public_key': self.eph_pub.encode().hex()}
        # immediate send
        self.sio.emit('handshake', data)
        # resend after delay so new clients also derive the key
        threading.Timer(1.0, lambda: self.sio.emit('handshake', data)).start()

    def on_handshake(self, data):
        """
        Handle incoming handshake: derive session key.
        """
        peer_pub = PublicKey(bytes.fromhex(data['public_key']))
        self.session_key = derive_session_key(self.eph_priv, peer_pub)
        print('[*] Session established. You can start chatting.')
        self.msg_count = 0

    def send_chat(self, text):
        """
        Encrypt and send a chat message.
        """
        if not self.session_key:
            print('[-] No session key yet. Please wait for handshake.')
            return
        ciphertext = encrypt_message(self.session_key, text.encode())
        self.sio.emit('msg', {'body': ciphertext.hex()})
        self._after_message()

    def on_message(self, data):
        """
        Decrypt and display incoming messages.
        """
        if not self.session_key:
            return
        ciphertext = bytes.fromhex(data['body'])
        plaintext = decrypt_message(self.session_key, ciphertext)
        print(f'Peer: {plaintext.decode()}')
        self._after_message()

    def _after_message(self):
        """
        Increment message counter and rotate keys if threshold reached.
        """
        self.msg_count += 1
        if self.msg_count >= ROTATION_THRESHOLD:
            print('[*] Rotating keys for PFS...')
            self.rotate_keys()

    def rotate_keys(self):
        """
        Clear old key, generate new ephemeral pair, and handshake again.
        """
        self.session_key = None
        self.eph_priv, self.eph_pub = generate_ephemeral_keypair()
        self._send_handshake()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python -m client.app <server_url>')
        sys.exit(1)
    client = SecretSocketClient(sys.argv[1])
    client.start()
