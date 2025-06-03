SecretSocket
An end-to-end-encrypted WebSocket chat with perfect-forward-secrecy (PFS).

```plain text
SecretSocket/
├─ client/                # Browser UI (HTML/JS) or CLI
├─ server/
│  ├─ __init__.py
│  ├─ app.py              # Flask-SocketIO entrypoint
│  └─ crypto.py           # All E2EE logic
├─ tests/
│  └─ test_crypto.py
├─ docs/
│  ├─ threat-model.md
│  └─ protocol.md
├─ Dockerfile
├─ docker-compose.yml
└─ README.md
```
simply expalain
**SecretSocket** is a hands-on demo of how modern end-to-end encryption works in a live chat app. At its heart, you’ll build:

1. A **server** that merely forwards messages (it never sees your plaintext).
2. A **client** that

   * establishes a secret channel with another client via **X25519 key exchange**,
   * encrypts every chat message with **ChaCha20-Poly1305**, and
   * regularly rotates its ephemeral keys to ensure **perfect forward secrecy**.

---

## High-level flow

1. **Startup & Identity Keys**

   * Each user generates a long-term X25519 keypair (`static_priv`, `static_pub`).
   * You exchange those public keys out-of-band (e.g. QR code, copy-paste).

2. **Connection & Ephemeral Handshake**

   * User A opens a WebSocket to the Flask-SocketIO server.
   * A generates a fresh ephemeral keypair (`eA_priv`, `eA_pub`) and sends `eA_pub`.
   * B does the same (`eB_priv`, `eB_pub`).
   * Both sides compute a shared secret:

     ```python
     shared = Box(e_priv, peer_e_pub).shared_key()
     session_key = HKDF(shared)
     ```
   * Now A and B share a symmetric key nobody else knows.

3. **Encrypting & Sending Messages**

   * To send “Hello”, A does:

     ```python
     box = SecretBox(session_key)
     ciphertext = box.encrypt(b"Hello")  # embeds a random nonce
     ws.emit("msg", { "from": "A", "body": ciphertext })
     ```
   * The server simply does `socketio.emit(...)` to B.

4. **Receiving & Decrypting**

   * B receives the JSON blob, extracts `body`, and runs:

     ```python
     box = SecretBox(session_key)
     plaintext = box.decrypt(ciphertext)
     ```
   * B sees “Hello.”

5. **Perfect Forward Secrecy (PFS)**

   * After a set number of messages (e.g. every 20) or time interval, both clients silently repeat step 2 with brand-new ephemeral keys.
   * Old session keys are wiped from memory.
   * Even if someone steals today’s key, they can’t decrypt yesterday’s messages.

6. **Packet-Capture Demo**

   * Run Wireshark on the WebSocket port.
   * Observe that every packet payload is just random bytes.
   * Use your own decryption tool to show “only endpoints can read it.”

7. **Docker & Deployment**

   * Dockerize server + a pair of demo clients.
   * Deploy on a free tier (Render, Fly.io) so your professor can click “Try it live.”


so to kick start the project:
first we are writing script in server in order to stabilished the Handshakes proccess so that each user has an identity key.
next would be session key Shared secret known only to both endpoints.
