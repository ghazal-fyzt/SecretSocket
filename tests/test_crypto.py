import pytest
from client.crypto import (
    generate_ephemeral_keypair,
    derive_session_key,
    encrypt_message,
    decrypt_message,
)
from nacl.exceptions import CryptoError


def test_key_agreement_identical():
    """
    Test that two parties performing ECDH derive the same session key.
    """
    # Party A generates ephemeral keypair
    a_priv, a_pub = generate_ephemeral_keypair()
    # Party B generates ephemeral keypair
    b_priv, b_pub = generate_ephemeral_keypair()

    # Each derives a session key using their private and the other's public
    key_ab = derive_session_key(a_priv, b_pub)
    key_ba = derive_session_key(b_priv, a_pub)

    # Session keys must match
    assert key_ab == key_ba, "ECDH-derived session keys do not match"


def test_encrypt_decrypt_roundtrip():
    """
    Test that encrypting and then decrypting returns the original plaintext.
    """
    # Setup a shared session key via ECDH
    priv1, pub1 = generate_ephemeral_keypair()
    priv2, pub2 = generate_ephemeral_keypair()
    session_key = derive_session_key(priv1, pub2)

    # Original message
    plaintext = b"The quick brown fox jumps over the lazy dog"

    # Encrypt
    ciphertext = encrypt_message(session_key, plaintext)

    # Decrypt and verify
    decrypted = decrypt_message(session_key, ciphertext)
    assert decrypted == plaintext, "Decrypted text does not match the original"


def test_decrypt_with_wrong_key_fails():
    """
    Test that decryption with an incorrect session key raises an exception.
    """
    # Setup two distinct session keys
    priv1, pub1 = generate_ephemeral_keypair()
    priv2, pub2 = generate_ephemeral_keypair()
    correct_key = derive_session_key(priv1, pub2)

    # Generate a wrong session key by swapping B's keys
    wrong_key = derive_session_key(priv2, pub1)

    plaintext = b"Secret message"
    ciphertext = encrypt_message(correct_key, plaintext)

    # Attempt decryption with the wrong key
    with pytest.raises(CryptoError):
        decrypt_message(wrong_key, ciphertext)


def test_encrypt_benchmark(benchmark):
    """
    Benchmark the performance of the encryption function.
    """
    # Prepare session key and plaintext for benchmarking
    priv, pub = generate_ephemeral_keypair()
    peer_priv, peer_pub = generate_ephemeral_keypair()
    session_key = derive_session_key(priv, peer_pub)
    plaintext = b"x" * 1024  # 1 KB payload

    # Benchmark the encrypt_message function
    benchmark(lambda: encrypt_message(session_key, plaintext))
