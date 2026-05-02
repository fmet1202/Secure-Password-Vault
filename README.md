# Code Ge'ez | Secure Password Vault (S-SDLC Project)

![C](https://img.shields.io/badge/c-%2300599C.svg?style=for-the-badge&logo=c&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/postgresql-%23316192.svg?style=for-the-badge&logo=postgresql&logoColor=white)
![OpenSSL](https://img.shields.io/badge/OpenSSL-721412.svg?style=for-the-badge&logo=openssl&logoColor=white)
![Argon2](https://img.shields.io/badge/Argon2-Security-blue.svg)

**Code Ge'ez** is a "Secure by Design" password manager built in C. It strictly follows the **Secure System Development Life Cycle (S-SDLC)**, focusing on Zero-Knowledge architecture, memory safety, and OWASP vulnerability mitigation.

## 🎓 S-SDLC Compliance & Security Features

### Phase 1: Requirements & Misuse Mitigation
* **Zero-Knowledge Data (Confidentiality):** User credentials are encrypted at rest using **AES-256-GCM**.
* **Memory Hardening:** Mitigates RAM-dump abuse cases using Kernel-level `mlockall()` and `OPENSSL_cleanse()` to aggressively zeroize memory buffers.

### Phase 2: Secure Design (STRIDE Mitigated)
* **Spoofing / Tampering:** Strictly parameterized PostgreSQL queries (`PQexecParams`) eliminate SQL Injection.
* **Information Disclosure:** "Have I Been Pwned" breach audits are conducted using **k-Anonymity** (only the first 5 bytes of a SHA-1 hash leave the browser via the Web Crypto API).

### Phase 3: Secure Implementation (OWASP)
* **A01: Broken Access Control:** Enforced `WHERE user_id = $1` context on all database executions.
* **A02: Cryptographic Failures:** Master Passwords utilize **Argon2** key derivation.
* **A08: Software & Data Integrity:** CI/CD pipeline integrated via GitHub Actions running **cppcheck** Static Application Security Testing (SAST) on every push.

### Phase 4 & 5: Testing, Deployment & Hardening
* **Environment Hardening:** The local Mongoose web server enforces **HTTPS/TLS** with strict `HttpOnly` and `Secure` cookie attributes.
* **Anti-CSRF:** Forms are protected by 64-byte randomized cryptographic tokens tied to the session state.

## 📦 Installation

```bash
# 1. Install Dependencies (Debian/Ubuntu)
sudo apt update
sudo apt install build-essential libssl-dev libpq-dev libargon2-dev git

# 2. Clone & Build
git clone https://github.com/fmet1202/Secure-Password-Vault.git
cd Secure-Password-Vault
make clean
make

# 3. Generate TLS Certificates
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"

# 4. Run
./securevault_web
```

Access the vault at https://127.0.0.1:8443

Group 8: ኢትዮጵያ ትቅደም
software security title: Secure Password Vault
https://github.com/fmet1202/Secure-Password-Vault

group members                       ID
1.Fisiha Mengistu             1601533
2. Temesgen Melaku          1603516      
3. Bezawit Ayal                 1505402
4.Selamawit Derese          1602399
5. Zelalem Addis               1602890
6. Sosina Asrat                 1602859