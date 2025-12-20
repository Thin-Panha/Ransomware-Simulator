# 🛡️ Ransomware Simulator (Educational Project)
## Version: 1.0

> **⚠️ Disclaimer**
> This project is **STRICTLY FOR EDUCATIONAL PURPOSES**.
> It is designed to demonstrate how real-world ransomware works **in a safe, controlled, offline lab environment**.
> **DO NOT** use this project on real systems, real data, or without explicit permission.
>
> The author and contributors are **not responsible** for misuse.

---

## 📌 Project Overview

The **Ransomware Simulator** is a Python-based cybersecurity learning project that models the **core workflow of modern ransomware**, including:

* Asymmetric key generation (RSA)
* Hybrid encryption (RSA + AES-GCM)
* Victim-side file encryption
* Attacker-side decryption after "ransom payment"
* Automatic file-state detection (NONE / MIXED / FULL)
* Safe backup and recovery mechanisms

This simulator is intended for:

* Cryptography students
* Cybersecurity labs
* Malware analysis education
* Understanding ransomware behavior **without causing real harm**

---

## 🧠 How the Simulator Works

### 🔑 1. Key Generation (Attacker)

* Generates a **2048-bit RSA key pair**
* **Private key** is stored on the attacker side
* **Public key** is placed on the victim side
* Prevents key regeneration when encrypted files exist (safety feature)

### 📁 2. Backup Phase (Victim)

* All victim files are copied to a safe `Data_Backup/` directory
* Encrypted (`.enc`) files are **never backed up again**

### 🔒 3. Encryption Phase (Attack)

* Each file is encrypted using:

  * Random **AES-256-GCM** key per file
  * AES key encrypted using **RSA-OAEP (SHA-256)**
* Original plaintext files are deleted
* Output format:

  ```
  [12 bytes nonce]
  [4 bytes encrypted-key length]
  [RSA-encrypted AES key]
  [AES-GCM ciphertext]
  ```

### 🔓 4. Decryption Phase (After Ransom Paid)

* Requires the attacker’s **private RSA key**
* Restores original files
* Removes `.enc` files automatically

---

## 📂 Project Structure

```
Ransomware-Simulator/
│
├── .gitignore                  # Git ignore rules (keys, venv, backups, state)
├── main.py                     # Main simulator menu & state manager
├── simulator_state.json        # Auto-generated state file
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
│
├── Attack_side/
│   ├── create_key/
│   │   └── asymmetric.py       # RSA key generation
│   └── decryptor/
│       ├── decryptor.py        # File decryption logic
│       └── asym_private_key.pem
│
├── Victim_side/
│   ├── Data/                   # Victim files (lab files only!)
│   ├── Data_Backup/            # Automatic backup folder
│   └── encryptor/
│       ├── encryptor.py        # File encryption logic
│       └── asym_public_key.pem
│
└── venv/                        # Python virtual environment (recommended)
```

---

## 🧪 File State Detection

The simulator automatically scans the victim `Data/` folder and detects:

| State | Description                        |
| ----- | ---------------------------------- |
| NONE  | No encrypted files                 |
| MIXED | Both encrypted and plaintext files |
| FULL  | All files encrypted                |

This prevents:

* Double encryption
* Accidental key overwrite
* Permanent data loss

---

## 🖥️ Menu Options

```
1) Generate asymmetric RSA keys (Attacker)
2) Encrypt victim files (Ransomware attack)
3) Decrypt files (After ransom payment)
4) Exit
```

The menu dynamically adapts based on the detected file state.

---

## ⚙️ Installation & Setup

### 📥1. Cloning the Repository

Clone the project from GitHub:

```bash
git clone https://github.com/Thin-Panha/Ransomware-Simulator.git
cd Ransomware-Simulator
```

### ✅ 2. Create Virtual Environment (Recommended)

```bash
python -m venv venv
```

Activate it:

* **Windows (PowerShell)**

```bash
venv\Scripts\activate
```

* **Linux / macOS**

```bash
source venv/bin/activate
```

---

### ✅ 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

### ▶️ 4. Run the Simulator

```bash
python main.py
```

---

## 🔐 Cryptography Details

* **RSA**: 2048-bit key, OAEP padding, SHA-256
* **AES**: AES-256-GCM (authenticated encryption)
* **Nonce**: 12 bytes (recommended for GCM)
* **Key Handling**:

  * AES keys are wiped from memory after use
  * Public key is deleted after encryption

---

## 📦 Libraries Used

This project relies on the following Python libraries:

| Library | Purpose |
|-------|--------|
| `cryptography` | RSA key generation, AES-GCM encryption, OAEP padding |
| `os`, `sys` | File system access and process control |
| `json` | Simulator state persistence |
| `shutil` | Secure file backup operations |

All external dependencies are listed in **`requirements.txt`** and should be installed inside a virtual environment.

## 🛑 Safety Features

✔ Prevents encrypting already encrypted files
✔ Prevents decrypting when no encrypted files exist
✔ Blocks RSA key overwrite when encrypted files exist
✔ Automatic backup before encryption
✔ Works on **Windows, Linux, macOS**

---

## 📊 Realism Level (Simulation Accuracy)

This project is designed to be **approximately 70–80% similar to real ransomware behavior**, focusing on the **cryptographic and operational core**, while intentionally excluding dangerous components.

### ✅ What Is Realistic

* Hybrid encryption (**RSA + AES-GCM**)
* Per-file random AES keys
* Secure key encapsulation using RSA-OAEP
* Encrypted file format with metadata
* Secure deletion of plaintext files
* Attacker-held private key model
* Victim-side public key usage
* File-state detection (none / mixed / full)

### ❌ What Is Intentionally Missing

* No persistence mechanisms
* No privilege escalation
* No network communication (C2)
* No lateral movement
* No data exfiltration
* No ransom payment system
* No system-level damage

This balance ensures the simulator is **educational, ethical, and safe**, while still accurately demonstrating how modern ransomware operates internally.

---

## 📁 Version Control & Git Safety (.gitignore)

This project includes a carefully designed `.gitignore` file to ensure **sensitive, generated, and dangerous files are never committed**.

### Ignored on Purpose

* Virtual environments (`venv/`, `.venv/`)
* Generated simulator state (`simulator_state.json`)
* Victim backup data (`Victim_side/Data_Backup/`)
* Cryptographic keys (`*.pem`)
* Python cache, build, and test artifacts

⚠️ **Important**: Never commit private keys, encrypted victim data, or backups to a repository.

---

## 🛑 Safety Features

✔ Prevents encrypting already encrypted files
✔ Prevents decrypting when no encrypted files exist
✔ Blocks RSA key overwrite when encrypted files exist
✔ Automatic backup before encryption
✔ Works on **Windows, Linux, macOS**

---

## 🎓 Educational Use Cases

* Understanding ransomware internals
* Learning hybrid encryption systems
* Practicing malware-safe lab design
* Cryptography coursework
* Blue-team / DFIR analysis

---

## 🚫 What This Project Is NOT

❌ Not real ransomware
❌ Not persistent
❌ No network communication
❌ No data exfiltration
❌ No real ransom mechanism

---

## 📜 License

This project is released **for educational use only**.
You may study, modify, and extend it **for learning purposes**.

---

## ✨ Author Notes

This simulator was carefully designed to behave like real ransomware **without being dangerous**.
If you are studying cryptography or cybersecurity, this project demonstrates:

* Real encryption standards
* Safe malware simulation practices
* Responsible security research

---

## 📄 Project Report

A detailed academic report explaining the **design, cryptographic concepts, workflow, and security considerations** of this project is available here:

👉 **[Download Project Report (PDF)](./Ransomware_Simulator_report.pdf)**

> 📌 *Note:* Screenshots of program execution, encryption/decryption results, and file states are included in the report.

---

## 👤 Creator

**THIN PANHA**  
🎓 Student at **Cambodia Academy of Digital Technology (CADT)**  
📚 Major: **Telecommunications & Networking**  
🔐 Specialization: **Cybersecurity**  
🧪 Generation: **GEN 10**

📍 LinkedIn: [Panha Thin](https://www.linkedin.com/in/panha-thin/)

This project was developed as part of a **cryptography and cybersecurity learning initiative**, focusing on understanding ransomware internals in a **safe, ethical, and controlled environment**.

> **Stay curious. Stay ethical. Stay safe.** 🧠🔐
---