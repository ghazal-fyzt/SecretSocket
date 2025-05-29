"""
Handles ephemeral key generation, ECDH handshake, and session-key usage for SecretSocket.
"""

from nacl.public import PrivateKey, PublicKey, Box
from nacl.secret import SecretBox
from nacl.hash import sha256
from nacl.encoding import RawEncoder


def generate_ephemeral_keypair():
    """
    Generates an ephemeral X25519 keypair for this chat session.
    Every time two clients start a chat session, they each generate a brand-new random keypair.
    Rotating keys like this gives Perfect Forward Secrecy: if someone later steals today’s keys, they still can’t decrypt yesterday’s messages.
    
    Returns:
        eph_priv (PrivateKey): Your ephemeral private key.
        eph_pub (PublicKey): The corresponding ephemeral public key.
    """
    eph_priv = PrivateKey.generate()
    eph_pub = eph_priv.public_key
    return eph_priv, eph_pub


def derive_session_key(own_priv, peer_pub):
    """
    Computes a shared session key from your private key and the peer's public key.

    Args:
        own_priv (PrivateKey): Your ephemeral private key.
        peer_pub (PublicKey): The peer's ephemeral public key.

    Returns:
        session_key (bytes): A 32-byte symmetric key for message encryption.
    """
    # Perform ECDH to get raw shared secret
    box = Box(own_priv, peer_pub)
    shared_secret = box.shared_key()
    
    #The raw Diffie–Hellman output isn’t directly the right size or format for encryption keys.
    #We run it through a hash function (SHA-256) to produce a clean, 32-byte key
    # Derive a 256-bit key by hashing the shared secret (HKDF-like)
    session_key = sha256(shared_secret, encoder=RawEncoder)
    return session_key


def encrypt_message(session_key, plaintext):
    """
    Encrypts a plaintext message using ChaCha20-Poly1305 (SecretBox).

    Args:
        session_key (bytes): 32-byte symmetric key.
        plaintext (bytes): The message to encrypt.

    Returns:
        ciphertext (bytes): Encrypted message (includes nonce).
    """
    box = SecretBox(session_key)
    return box.encrypt(plaintext)


def decrypt_message(session_key, ciphertext):
    """
    Decrypts a ciphertext produced by `encrypt_message`.

    Args:
        session_key (bytes): 32-byte symmetric key.
        ciphertext (bytes): The data to decrypt.

    Returns:
        plaintext (bytes): The original message.
    """
    box = SecretBox(session_key)
    return box.decrypt(ciphertext)
