"""
Generate and display a long-term X25519 keypair using PyNaCl.
"""

from nacl.public import PrivateKey, PublicKey


def generate_keypair():
    """
    Generate a long-term X25519 keypair.

    Returns:
        sk (PrivateKey): The private key object.
        pk (PublicKey): The public key object.

    Prints both keys in hexadecimal for easy copy-paste exchange.
    """
    # Create a new private (secret) key
    sk = PrivateKey.generate()
    # Derive the corresponding public key
    pk = sk.public_key

    # Encode keys as hex strings for storage/display
    sk_hex = sk.encode().hex()
    pk_hex = pk.encode().hex()

    print("=== Generated X25519 Keypair ===")
    print(f"PRIVATE_KEY (keep secret!): {sk_hex}")
    print(f"PUBLIC_KEY  (share this):   {pk_hex}")

    return sk, pk


if __name__ == "__main__":
    # When run directly, generate and show the keypair
    generate_keypair()
