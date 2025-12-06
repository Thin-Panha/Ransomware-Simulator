import os
import shutil

DATA_FOLDER = "../Data"
BACKUP_FOLDER = "../Data_Backup"

def backup_files():
    try:
        if not os.path.exists(DATA_FOLDER):
            raise Exception(f"'{DATA_FOLDER}' folder does not exist.")

        files = os.listdir(DATA_FOLDER)
        files = [f for f in files if os.path.isfile(os.path.join(DATA_FOLDER, f))]

        if not files:
            raise Exception(f"No files found in '{DATA_FOLDER}' folder to backup.")
        else:
            # Create backup folder if missing
            if not os.path.exists(BACKUP_FOLDER):
                os.makedirs(BACKUP_FOLDER)
        for filename in files:
            src = os.path.join(DATA_FOLDER, filename)
            dst = os.path.join(BACKUP_FOLDER, filename)

            try:
                shutil.copy2(src, dst)
                print(f"[+] Backed up: {filename}")
            except Exception as e:
                print(f"[ERROR] Failed to back up {filename}: {e}")

        print("[✓] Backup completed.")
    except Exception as err:
        print(f"[FATAL ERROR] {err}")


if __name__ == "__main__":
    backup_files()
