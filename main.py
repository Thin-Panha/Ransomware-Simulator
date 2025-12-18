import os
import json
import sys

# --- Import modules from Attacker Side ---
from Attack_side.create_key import asymmetric
from Attack_side.decryptor import decryptor

# --- Import modules from Victim Side ---
from Victim_side.encryptor import encryptor
from Victim_side.backup import backup

STATE_FILE = "simulator_state.json"
DATA_FOLDER = "./Victim_side/Data"

def scan_data_folder_for_encryption():
    """
    Scans Data/ folder and returns:
    - "none"   → no encrypted files
    - "full"   → all are encrypted (.enc)
    - "mixed"  → contains BOTH encrypted and unencrypted files
    """

    if not os.path.exists(DATA_FOLDER):
        return "none"

    encrypted = 0
    normal = 0

    for f in os.listdir(DATA_FOLDER):
        full_path = os.path.join(DATA_FOLDER, f)

        if os.path.isdir(full_path):
            continue  # ignore folders

        if f.endswith(".enc"):
            encrypted += 1
        else:
            normal += 1

    if encrypted == 0:
        return "none"
    elif normal == 0:
        return "full"
    else:
        return "mixed"


# ----------------------------------------------------
#                STATE MANAGEMENT
# ----------------------------------------------------

# def load_state():
#     # Load previous state if exists
#     if os.path.exists(STATE_FILE):
#         with open(STATE_FILE, "r") as f:
#             state = json.load(f)
#     else:
#         state = {"keys_generated": False, "files_encrypted": False}

#     # Scan Data/ folder for encryption status
#     real_state = scan_data_folder_for_encryption()
#     private_key = decryptor.load_rsa_private_key()
#     if private_key is None:
#         state["keys_generated"] = False
#     # Convert to boolean for legacy compatibility
#     state["files_encrypted"] = (real_state == "full")

#     state["file_state"] = real_state  # NEW FIELD

#     save_state(state)

#     return state

def load_state():
    # Base state
    state = {
        "keys_generated": False,
        "files_encrypted": False,
        "file_state": "none"
    }

    # Load old state if exists (only for keys)
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            old_state = json.load(f)
            state["keys_generated"] = old_state.get("keys_generated", False)

    # --- REAL STATE FROM FILESYSTEM ---
    real_state = scan_data_folder_for_encryption()
    state["file_state"] = real_state
    state["files_encrypted"] = (real_state in ["full", "mixed"])

    # Check private key existence
    if decryptor.load_rsa_private_key() is None:
        state["keys_generated"] = False

    save_state(state)
    return state


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=4)


# ----------------------------------------------------
#                RANSOMWARE SIMULATOR BANNER
# ----------------------------------------------------
def banner():
    print(r"""
=========================================================
            ████  RANSOMWARE SIMULATOR  ████
      Educational Cybersecurity Encryption Demonstrator
=========================================================

This simulator models real ransomware behavior:
 • The attacker generates asymmetric RSA keys
 • Victim's files are backed up
 • Victim's files are encrypted using RSA + AES-GCM
 • Victim can decrypt files only after ransom is "paid"

=========================================================
""")

def generate_keys(state):

    file_state = state.get("file_state", "none")

    if file_state == "full":
        print("\n[!] ERROR: All files are encrypted.")
        print("[!] Generating new keys NOW would make recovery impossible.")
        print("[!] Operation blocked for safety.")
        return

    if file_state == "mixed":
        # not
        print("\n[!] Mixed file state detected:")
        print("    - Some files are encrypted")
        print("    - Some files are original")
        print("\n[!] Generating NEW KEYS may cause permanent loss of the")
        print("    already-encrypted files.")
        confirm = input("Proceed anyway? (y/N): ").lower()
        if confirm != "y":
            print("[-] Key generation canceled.")
            return

    if state["keys_generated"]:
        print("\n[!] Keys already exist.")
        confirm = input("Overwrite existing keys? (y/N): ").lower()
        if confirm != "y":
            print("[-] Key generation canceled.")
            return

    print("\n[*] Generating RSA keys...")

    try:
        private_key, public_key = asymmetric.generate_rsa_keys()
        pri_dir, pub_dir = asymmetric.prepare_folders()
        asymmetric.save_keys(private_key, public_key, pri_dir, pub_dir)
        print("\n[✓] RSA Key Pair Generated Successfully.")
        # private_key = decryptor.load_rsa_private_key()
        # if private_key is None:
        #     state["keys_generated"] = True
          
        state["keys_generated"] = True
        save_state(state)
    except Exception as e:
        print(f"[ERROR] Failed to generate keys: {e}")

def start_encryption(state):

    file_state = state.get("file_state", "none")

    if not state["keys_generated"]:
        print("[X] ERROR: You must generate RSA keys before encryption!")
        return

    if file_state == "full":
        print("[!] All files already encrypted!")
        return

    if file_state == "mixed":
        print("\n[!] Mixed state detected:")
        print("    ✓ Will encrypt ONLY original files")
        print("    ✗ Will NOT touch existing .enc files")

        confirm = input("Continue encryption? (y/N): ").lower()
        if confirm != "y":
            print("[-] Encryption canceled.")
            return

    try:
        public_key = encryptor.load_rsa_public_key()
        if public_key is None:
            print("[X] ERROR: Public key cannot be loaded.")
            return
        
        if file_state != "mixed":
            print("\n[*] Creating backup...")
            backup.backup_files()

        print("\n[*] Encrypting victim files...")
        encryptor.encrypt_all_files(public_key, skip_encrypted=True)

        state["files_encrypted"] = True
        save_state(state)

        print("\n[✓] Files encrypted successfully.")

    except Exception as e:
        print(f"[ERROR] Encryption failed: {e}")


# ----------------------------------------------------
#                DECRYPTION PROCESS
# ----------------------------------------------------
# def start_decryption(state):
#     file_state = state.get("file_state", "none")
#     # if not state["files_encrypted"]:
#     if not file_state == "mixed":
#         print("[X] ERROR: No encrypted files detected.")
#         return

#     print("\n====================================================")
#     print("       🔓 DECRYPTION UNLOCKED — RANSOM PAID 🔓")
#     print("====================================================\n")

#     try:
#         private_key = decryptor.load_rsa_private_key()
#         if private_key is None:
#             print("[X] ERROR: Private key missing — cannot decrypt!")
#             return

#         decryptor.decrypt_all_files(private_key)

#         state["files_encrypted"] = False
#         save_state(state)

#         print("\n[✓] Files successfully decrypted.")

#     except Exception as e:
#         print(f"[ERROR] Decryption failed: {e}")

def start_decryption(state):
    file_state = state.get("file_state", "none")

    if file_state == "none":
        print("[X] ERROR: No encrypted files detected.")
        return

    print("\n====================================================")
    print("       🔓 DECRYPTION UNLOCKED — RANSOM PAID 🔓")
    print("====================================================\n")

    try:
        private_key = decryptor.load_rsa_private_key()
        if private_key is None:
            print("[X] ERROR: Private key missing — cannot decrypt!")
            return

        decryptor.decrypt_all_files(private_key)

        save_state(load_state())  # re-scan after decrypt

        print("\n[✓] Files successfully decrypted.")

    except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")


# ----------------------------------------------------
#                MAIN MENU
# ----------------------------------------------------
def menu():
    print(f"""
Choose an option:
1) Generate asymmetric RSA keys (Attacker)       
2) Encrypt victim files (Ransomware attack)
3) Decrypt files (After ransom payment)
4) Exit   
""")
    return input("Enter your choice: ").strip()


# ----------------------------------------------------
#                MAIN PROGRAM START
# ----------------------------------------------------
if __name__ == "__main__":
    banner()
    state = load_state()

    while True:
        state = load_state()  # AUTO-SCAN before showing menu
        choice = menu()

        if choice == "1":
            generate_keys(state)

        elif choice == "2":
            state = load_state()  # scan again before encryption
            start_encryption(state)

        elif choice == "3":
            state = load_state()  # scan again before decryption
            start_decryption(state)

        elif choice == "4":
            print("\nExiting ransomware simulator. Stay safe!")
            state = load_state() 
            sys.exit()

        else:
            print("[!] Invalid choice, try again.")
