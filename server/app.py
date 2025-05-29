"""
Minimal Flask-SocketIO server for SecretSocket.
Relays handshake and chat messages between connected clients.
Does NOT decrypt or inspect message contents—acts as an honest-but-curious relay.
"""

from flask import Flask, request
from flask_socketio import SocketIO, emit

# Initialize Flask app and Socket.IO
app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace-with-a-secure-random-key'
# Allow all origins for simplicity; restrict in production!
socketio = SocketIO(app, cors_allowed_origins='*')

@socketio.on('connect')
def handle_connect():
    """
    Called when a new client connects.
    Logs the client's session ID.
    """
    print(f'[+] Client connected: {request.sid}')

@socketio.on('disconnect')
def handle_disconnect():
    """
    Called when a client disconnects.
    Logs the client's session ID.
    """
    print(f'[-] Client disconnected: {request.sid}')

@socketio.on('handshake')
def handle_handshake(data):
    """
    Receives an ephemeral public key from one client and forwards it to all other clients.
    data: { 'public_key': <hex-string> }
    """
    print(f"[*] Handshake from {request.sid}: {data['public_key']}")
    # Broadcast to others (exclude the sender)
    emit('handshake', data, broadcast=True, include_self=False)

@socketio.on('msg')
def handle_message(data):
    """
    Receives an encrypted chat message and relays it to other clients.
    data: { 'body': <ciphertext-hex> }
    """
    print(f"[*] Message from {request.sid}: {data['body'][:16]}... (truncated)")
    # Broadcast to others (exclude the sender)
    emit('msg', data, broadcast=True, include_self=False)

if __name__ == '__main__':
    # Run the server on port 5000, accessible from any network interface
    socketio.run(app, host='0.0.0.0', port=5000)  # debug=True can help during development
