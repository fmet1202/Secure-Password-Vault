# Secure System Development Life Cycle (S-SDLC) Report
**Project Title:** Code Ge'ez - Zero-Knowledge Secure Password Vault  
**Course:** Secure Software Systems Development  

---

## Phase 1: Initiation & Requirement Engineering

### 1.1 Information Statement & Risk Assessment
In accordance with **NIST SP 800-53 (Control AC-2, SC-28: Protection of Information at Rest)**, the Code Ge'ez application handles highly sensitive User Credentials. A compromise of this system would lead to severe confidentiality breaches. Therefore, the system is engineered under a "Zero-Knowledge" paradigm, ensuring that even if the host server is fully compromised, the plaintext data remains mathematically inaccessible without the user's explicit runtime authorization.

### 1.2 Confidentiality, Integrity, and Availability (CIA)
* **Confidentiality:** All vault entries are symmetrically encrypted using AES-256-GCM. Decryption keys are never written to disk.
* **Integrity:** The use of Galois/Counter Mode (GCM) provides cryptographic authentication tags. If an attacker tampers with the ciphertext in the PostgreSQL database, the decryption process will intentionally fail.
* **Availability:** The application utilizes a non-blocking event-driven architecture (Mongoose) to mitigate resource-exhaustion Denial of Service (DoS) attacks.

### 1.3 Core Security Requirements ("Shall" Statements)
1. **REQ-01:** The system *shall* hash all Master Passwords using the Argon2 key derivation function before authenticating.
2. **REQ-02:** The system *shall* encrypt all vault payloads using AES-256-GCM before database insertion.
3. **REQ-03:** The system *shall* strictly enforce TLS/HTTPS for all client-server communication.
4. **REQ-04:** The system *shall* utilize cryptographically secure, randomized Anti-CSRF tokens for all state-changing HTTP POST requests.
5. **REQ-05:** The system *shall* lock process memory (`mlockall()`) to prevent sensitive cryptographic material from paging to the disk swap.

### 1.4 Abuse Cases
* **Abuse Case 1:** An attacker gains access to the physical server and attempts to dump the RAM to extract the master password.
  * *Mitigation:* OS-Level Memory Hardening (`mlockall()`) and aggressive memory zeroization (`OPENSSL_cleanse()`).
* **Abuse Case 2:** An attacker conducts a Man-in-the-Middle (MitM) attack to steal the session cookie.
  * *Mitigation:* Enforced TLS (HTTPS) and `Secure` / `HttpOnly` cookie flags.
* **Abuse Case 3:** An attacker intercepts the "Breach Audit" network request to steal the user's password.
  * *Mitigation:* The system uses **k-Anonymity**. The password is hashed locally (SHA-1), and only the first 5 characters of the hash are sent to the external API.

---

## Phase 2: Secure Design (Development/Acquisition)

### 2.1 Threat Modeling (STRIDE Analysis)
| Threat Category | Identified Risk | Architectural Mitigation |
| :--- | :--- | :--- |
| **S**poofing | Attacker forges an authenticated session. | 64-byte randomized session IDs generated via `RAND_bytes`. |
| **T**ampering | SQL Injection to modify the backend database. | Strict implementation of PostgreSQL parameterized queries (`PQexecParams`). |
| **R**epudiation | User denies creating a specific vault entry. | Backend maps every transaction directly to the authenticated `user_id` session state. |
| **I**nfo Disclosure | Passwords leak during third-party breach audits. | Client-side **k-Anonymity** ensures plaintext never leaves the browser. |
| **D**enial of Service | Brute-forcing the login endpoint crashes the CPU. | Rate limiting mechanisms and Argon2 memory-hard hashing slows down brute force vectors. |
| **E**levation of Privilege | User accesses another user's vault entries (IDOR). | Backend mandates `WHERE user_id = $1` on every single database transaction. |

### 2.2 Attack Tree Diagram
**Target Asset: The User Database (vault.db)**
```text
[GOAL] Steal and Decrypt User Passwords
 ├──[ATTACK PATH 1] Intercept Data in Transit (Man-in-the-Middle)
 │    └── [MITIGATION] Enforced TLS/HTTPS.
 │
 ├──[ATTACK PATH 2] Bypass Authentication & Hijack Sessions
 │    ├── Threat: Cross-Site Request Forgery (CSRF)
 │    │    └── [MITIGATION] 64-byte randomized Anti-CSRF tokens.
 │    └── Threat: Session Cookie Theft
 │         └── [MITIGATION] 'HttpOnly', 'Secure', and 'SameSite=Lax' flags.
 │
 ├── [ATTACK PATH 3] Breach the Database via Web Vulnerability
 │    └── Threat: SQL Injection (OWASP A03:2021)
 │         └──[MITIGATION] Parameterized queries (PQexecParams).
 │
 └── [ATTACK PATH 4] Extract Cryptographic Keys from Server RAM
      ├── Threat: Inspecting Swap/Pagefile on Hard Drive
      │    └── [MITIGATION] `mlockall()` prevents the Linux kernel from writing RAM to disk.
      └── Threat: RAM Scraping after execution
           └── [MITIGATION] `OPENSSL_cleanse()` instantly zeroizes buffers.
```

---

## Phase 3: Secure Implementation

### 3.1 OWASP Top 10 Mitigation Standards
* **A01:2021 - Broken Access Control:** Addressed by strictly enforcing the authenticated session context. No user can view, edit, or delete an entry without passing the `WHERE user_id = $1` database check.
* **A02:2021 - Cryptographic Failures:** Mitigated by utilizing industry-standard algorithms (Argon2 for key derivation, AES-256-GCM for symmetric encryption, OpenSSL RAND_bytes for CSPRNG generation).
* **A03:2021 - Injection:** Handled comprehensively. String concatenation is never used to construct SQL queries. The libpq library handles automatic sanitization via `PQexecParams`.

### 3.2 Static Analysis (SAST) Implementation
A Continuous Integration (CI) pipeline was built using GitHub Actions. Upon every code push, a cloud server compiles the C codebase and runs cppcheck (Static Application Security Testing).
* **Scan Results:** The SAST pipeline confirmed zero memory leaks, zero buffer overflows, and zero uninitialized variable vulnerabilities.

---

## Phase 4: Testing & Validation

### 4.1 Vulnerability Assessment (Dynamic Testing)
Manual Penetration Testing (DAST) was conducted against the running application to validate the security controls defined in Phase 1.

| Test Case | Description | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| TC-01 (SQLi) | Attempt to bypass login using `' OR '1'='1` in the username field. | Authentication fails. Input is treated strictly as a string literal. | Auth Failed. | PASS |
| TC-02 (XSS) | Inject `<script>alert(1)</script>` into the vault "Site" input field. | Script is sanitized and rendered as plaintext, preventing execution. | Rendered safely. | PASS |
| TC-03 (MitM) | Attempt to load the application over `http://` instead of `https://`. | Connection is refused. TLS handshake is strictly mandated. | Connection Dropped. | PASS |
| TC-04 (CSRF) | Attempt to submit a POST request to `/vault/delete` without a valid token. | Server drops request and redirects with a CSRF error message. | Redirected (Error). | PASS |

### 4.2 Requirements Traceability
All 5 functional security requirements defined in Phase 1 (Encryption, TLS, Argon2, CSRF, and Memory Locking) were verified as active and functional during the Dynamic Testing phase.

---

## Phase 5: Deployment & Maintenance

### 5.1 Hardening Guide (Secure Deployment)
To securely deploy the Code Ge'ez application, the following hardening steps are enforced in the production environment:
* **Network Security:** The application runs on port 8443, mitigating the need for Root privileges to bind to standard ports (80/443).
* **Transport Security:** Locally generated `cert.pem` and `key.pem` files are required for the Mongoose server to start.
* **OS Security:** The host machine must grant permissions to lock memory pages to ensure `mlockall()` executes successfully, preventing disk-swap leaks.

### 5.2 Patch Management & Zero-Day Protocol
To ensure long-term resilience against emerging threats:
* **Monitoring:** GitHub Dependabot is utilized to monitor updates for C libraries (`libssl-dev`, `libpq-dev`, `libargon2-dev`).
* **Incident Response:** In the event of a Zero-Day vulnerability in OpenSSL or PostgreSQL:
  1. The server is temporarily taken offline (air-gapped).
  2. Host-level package managers (apt / pacman) are utilized to pull upstream security patches.
  3. The application is recompiled using `make clean && make`.
  4. A mandatory Master Password cycle is triggered for all registered users if a cryptographic primitive is compromised.
