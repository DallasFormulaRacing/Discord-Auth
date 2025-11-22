#!/usr/bin/env python3
"""
Generate RSA keypair for JWT signing.
Run this once during setup.

This is ALL AI GENERATED CODE, its just used for generating local keys for testing purposes.
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os


def generate_rsa_keypair(
    private_key_path="private_key.pem", public_key_path="public_key.pem"
):
    """Generate RSA keypair and save to PEM files."""

    # Check if keys already exist
    if os.path.exists(private_key_path) or os.path.exists(public_key_path):
        response = input("Keys already exist. Overwrite? (yes/no): ")
        if response.lower() != "yes":
            print("Aborted.")
            return

    print("Generating RSA keypair (2048 bits)...")

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Get public key
    public_key = private_key.public_key()

    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Write keys to files
    with open(private_key_path, "wb") as f:
        f.write(private_pem)
    print(f"✓ Private key written to {private_key_path}")

    with open(public_key_path, "wb") as f:
        f.write(public_pem)
    print(f"✓ Public key written to {public_key_path}")

    # Set restrictive permissions on private key
    os.chmod(private_key_path, 0o600)
    print(f"✓ Set permissions on {private_key_path} to 600")

    print("\n✅ RSA keypair generated successfully!")
    print("\nIMPORTANT:")
    print("- Keep private_key.pem SECRET and SECURE")
    print("- Add private_key.pem to .gitignore")
    print("- Back up your private key securely")


if __name__ == "__main__":
    generate_rsa_keypair()
