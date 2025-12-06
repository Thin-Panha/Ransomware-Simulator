import os
import platform
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_rsa_keys():
    # Generate RSA private and public keys
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key

    except Exception as e:
        print(f"[ERROR] Failed to generate RSA keys: {e}")
        return None, None


def prepare_folders():
    # Create folder structure in a safe, cross-platform way
    try:
        key_dir = os.path.join(os.getcwd(), "../Key")
        victim_dir = os.path.join(os.getcwd(), "../Victim")

        os.makedirs(key_dir, exist_ok=True)
        os.makedirs(victim_dir, exist_ok=True)

        print(f"[+] Folders ready: {key_dir}, {victim_dir}")
        return key_dir, victim_dir

    except Exception as e:
        print(f"[ERROR] Failed to create directories: {e}")
        return None, None


def save_keys(private_key, public_key, key_dir, victim_dir):
    # Save RSA keys to PEM files
    try:
        # File paths (cross-platform safe)
        private_file = os.path.join(key_dir, "private_key.pem")
        public_file = os.path.join(victim_dir, "public_key.pem")

        # Save private key
        with open(private_file, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        # Save public key
        with open(public_file, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        print("[✓] Keys saved successfully.")
        print(f"    → {private_file}")
        print(f"    → {public_file}")

    except Exception as e:
        print(f"[ERROR] Failed to save keys: {e}")


def main():
    print("[+] Running on:", platform.system())

    private_key, public_key = generate_rsa_keys()
    if private_key is None:
        print("[!] Key generation failed.")
        return

    key_dir, victim_dir = prepare_folders()
    if key_dir is None:
        print("[!] Directory setup failed.")
        return

    save_keys(private_key, public_key, key_dir, victim_dir)
    print("[✓] Done.")


if __name__ == "__main__":
    main()
