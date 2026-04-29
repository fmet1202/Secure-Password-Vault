# Code Ge'ez | Secure Vault

![C](https://img.shields.io/badge/c-%2300599C.svg?style=for-the-badge&logo=c&logoColor=white)
![SQLite](https://img.shields.io/badge/sqlite-%2307405e.svg?style=for-the-badge&logo=sqlite&logoColor=white)
![OpenSSL](https://img.shields.io/badge/OpenSSL-721412.svg?style=for-the-badge&logo=openssl&logoColor=white)
![TailwindCSS](https://img.shields.io/badge/tailwindcss-%2338B2AC.svg?style=for-the-badge&logo=tailwind-css&logoColor=white)
![JavaScript](https://img.shields.io/badge/javascript-%23323330.svg?style=for-the-badge&logo=javascript&logoColor=%23F7DF1E)

**Code Ge'ez** is a lightning-fast, locally hosted, zero-knowledge password manager. It combines a highly optimized pure C backend with a sleek, modern glassmorphic web interface.

Built for cybersecurity professionals, homelab enthusiasts, and anyone who demands absolute control over their cryptographic keys without relying on third-party cloud providers.

---

## 🛡️ Core Security Features

- **AES-256-GCM Encryption:** All vault entries are symmetrically encrypted using military-grade authenticated encryption.
- **PBKDF2-HMAC Key Derivation:** Master passwords are never stored. They are hashed using PBKDF2 with high iteration counts and unique salts.
- **Zero-Knowledge Architecture:** The database (`vault.db`) only stores encrypted ciphertexts and initialization vectors (IVs). Without the Master Password, the data is mathematically unreadable.
- **Memory Zeroization:** Sensitive buffers containing plaintext passwords or cryptographic keys are securely scrubbed from RAM (`OPENSSL_cleanse`) immediately after use.
- **CSRF Protection:** All web forms are protected by cryptographically secure, randomized Anti-CSRF tokens.

## 🚀 Tech Stack

* **Backend:** Pure C using the [Mongoose](https://mongoose.ws/) networking library.
* **Database:** SQLite3 (Local, serverless SQL).
* **Cryptography:** OpenSSL (libcrypto).
* **Frontend:** Vanilla HTML5, JavaScript, and Tailwind CSS (Dark Mode Glassmorphism UI).

## 📦 Installation & Setup

### Prerequisites

You need a C compiler (GCC/Clang), SQLite3, and OpenSSL development headers.

**Arch Linux:**
```bash
sudo pacman -S base-devel openssl sqlite git
```

**Debian / Ubuntu / Kali:**
```bash
sudo apt update
sudo apt install build-essential libssl-dev libsqlite3-dev git
```

**macOS:**
```bash
brew install openssl sqlite git
```

## Build Instructions

1. Clone the repository:
```bash
git clone https://github.com/fmet1202/Secure-Password-Vault.git
cd Secure-Password-Vault
```

2. Compile the application using the provided Makefile:
```bash
make clean
make
```

3. Start the Vault Server:
```bash
./securevault_web
```

4. Access the interface:
   Open your web browser and navigate to `http://127.0.0.1:8443`

## 🧠 Architecture Notes

Code Ge'ez utilizes a highly efficient Server-Side Rendering (SSR) Template Substitution model.
Instead of writing complex C code to generate HTML nodes or relying on heavy frontend frameworks, the C backend simply reads raw `.html` files from the `assets/` directory and performs fast string replacements (e.g., `{{MESSAGE}}`, `{{VAULT_ENTRIES}}`).

This guarantees:

- **Zero Segmentation Faults** during UI updates.
- **Complete separation** of frontend design and backend cryptographic logic.
- **Sub-millisecond response times.**

## ⚠️ Disclaimer

This software is provided "as-is". While it utilizes industry-standard cryptographic libraries (OpenSSL), it is a self-hosted project. You are solely responsible for managing your firewall, securing your host machine, and backing up your `vault.db` file. If you lose your Master Password, your data cannot be recovered.
