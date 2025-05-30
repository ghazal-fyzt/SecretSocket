"""
Flask-SocketIO server for SecretSocket.
Relays handshake and chat messages between connected clients.
Does NOT decrypt or inspect message contents—acts as an honest-but-curious relay.
"""
print(">>> Starting SecretSocket server…")  # just because:)

from flask import Flask, request
from flask_socketio import SocketIO, emit

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace-with-a-secure-random-key'

# Healthcheck route to verify server is running
@app.route('/')
def index():
    return "🔒 SecretSocket server is running!"

# Initialize Socket.IO with CORS allowed for all origins (development only)
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
    print(f"[*] Handshake from {request.sid}: {data.get('public_key')}")
    # Relay to all other clients
    emit('handshake', data, broadcast=True, include_self=False)

@socketio.on('msg')
def handle_message(data):
    """
    Receives an encrypted chat message and relays it to other clients.
    data: { 'body': <ciphertext-hex> }
    """
    print(f"[*] Message from {request.sid}: {str(data.get('body'))[:16]}... (truncated)")
    # Relay to all other clients
    emit('msg', data, broadcast=True, include_self=False)

if __name__ == '__main__':
    # Start the Socket.IO server on port 5000
    socketio.run(app, host='0.0.0.0', port=5000)
