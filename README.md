# SecretSocket
An end-to-end-encrypted WebSocket chat with perfect-forward-secrecy (PFS).


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
