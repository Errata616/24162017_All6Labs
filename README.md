# Cryptography & Applications — Laboratory Project

This repository contains the C++ implementations for the required cryptography laboratories:

- **Lab 1:** Symmetric encryption with Crypto++
- **Lab 3:** RSA-OAEP and hybrid encryption
- **Lab 4:** Hashing, X.509/PKI, MD5 collision analysis, and length-extension attacks
- **Lab 5:** Classical digital signatures with ECDSA and RSA-PSS
- **Lab 6:** Post-quantum signatures, KEMs, and a minimal PQ certificate model

---

## 1. Project Structure

```text
Cryptography_C++/
├── CMakeLists.txt
├── README.md
├── Lab1/
│   └── Lab1.cpp
├── Lab3/
│   └── Lab3.cpp
├── Lab4/
│   └── Lab4.cpp
├── Lab5/
│   └── Lab5.cpp
├── Lab6/
│   └── Lab6.cpp
├── tests/
├── results/
└── build/
```

The `build/` directory is generated locally and should not be committed to source control.

---

## 2. Implemented Features

### Lab 1 — Symmetric Encryption

Implemented with **Crypto++**.

Supported modes:

- AES-ECB
- AES-CBC
- AES-CFB
- AES-OFB
- AES-CTR
- AES-XTS
- AES-CCM
- AES-GCM

Additional features:

- AES-128, AES-192, and AES-256 key generation
- Binary-safe file input/output
- UTF-8 text input
- Raw, hexadecimal, and Base64 output
- Secure random key and IV/nonce generation
- AAD support for CCM and GCM
- Authentication-tag verification
- Nonce-reuse detection for CTR, CCM, and GCM
- ECB warning and 16 KiB restriction
- NIST/RFC known-answer tests
- Automated negative tests
- Performance benchmarking

### Lab 3 — RSA-OAEP and Hybrid Encryption

Implemented with **OpenSSL**.

Supported features:

- RSA-3072 and RSA-4096 key generation
- RSA-OAEP with SHA-256 and MGF1-SHA-256
- Optional OAEP labels
- PEM and DER key output
- RSA plaintext-size validation
- Automatic hybrid encryption for large input
- AES-256-GCM data encryption
- RSA-OAEP wrapping of the AES key
- JSON hybrid-envelope format
- Authentication-tag verification
- Manual OAEP encode/decode demonstration
- Negative tests for tampering, wrong keys, wrong labels, malformed envelopes, and corrupted PEM files

### Lab 4 — Hashing, PKI, and Practical Attacks

Implemented with **OpenSSL** and Crypto++ where appropriate.

Supported hash algorithms:

- SHA-224
- SHA-256
- SHA-384
- SHA-512
- SHA3-224
- SHA3-256
- SHA3-384
- SHA3-512
- SHAKE128
- SHAKE256

Additional features:

- Streaming file hashing
- Variable SHAKE output length
- X.509 certificate parsing
- Subject, issuer, validity, SAN, key usage, public-key, and signature-algorithm extraction
- Certificate-signature verification with an issuer certificate
- MD5 collision comparison support
- Naive `SHA256(key || message)` MAC demonstration
- HMAC-SHA256 comparison
- SHA-256 length-extension attack demonstration
- Automated correctness and negative tests

### Lab 5 — Classical Digital Signatures

Implemented with **OpenSSL**.

Supported algorithms:

- ECDSA with P-256 and SHA-256
- RSA-PSS-3072 with SHA-256
- RSA-PSS salt length equal to the SHA-256 digest length

Additional features:

- PEM key generation
- Detached signatures
- Signature verification
- Tampered-message and tampered-signature detection
- Wrong-public-key detection
- Automated self-tests
- Performance benchmarking

### Lab 6 — Post-Quantum Cryptography

Implemented with **OpenSSL provider-based PQC support**.

Supported algorithms:

- ML-DSA-44
- ML-DSA-65
- ML-KEM-512
- ML-KEM-768

Additional features:

- ML-DSA key generation, signing, and verification
- ML-KEM key generation, encapsulation, and decapsulation
- Shared-secret comparison
- Batch signature verification
- Batch KEM decapsulation
- Minimal ML-DSA-signed certificate structure
- Certificate tamper detection
- Automated correctness and negative tests
- Performance benchmarking

---

## 3. Requirements

### Common

- CMake 3.20 or newer
- A C++17-compatible compiler
- Git
- Ninja, MinGW-w64, MSVC, GCC, or Clang

### Cryptographic Libraries

- **Crypto++** for Lab 1
- **OpenSSL 4.0.x** targeted for Labs 3, 4, 5, and 6
- OpenSSL must provide the algorithms required by the selected Lab 6 configuration, including ML-DSA and ML-KEM support

The project should also work with a compatible OpenSSL installation that exposes the same required EVP interfaces and algorithm providers.

---

## 4. Windows Setup

Recommended tools:

- Visual Studio Build Tools or MinGW-w64
- CMake
- Ninja
- Crypto++
- OpenSSL 4.0.x

Verify the tools:

```powershell
cmake --version
g++ --version
openssl version -a
```

Configure the project:

```powershell
cmake -S . -B build -DBUILD_TESTING=ON
```

Build:

```powershell
cmake --build build
```

For a multi-configuration generator such as Visual Studio:

```powershell
cmake --build build --config Release
```

---

## 5. Ubuntu Setup

Install the build tools:

```bash
sudo apt update
sudo apt install -y build-essential cmake ninja-build git pkg-config
```

Install Crypto++ development files:

```bash
sudo apt install -y libcrypto++-dev libcrypto++-utils
```

OpenSSL must be installed in a version that provides the APIs and algorithms required by Labs 3–6.

Verify the environment:

```bash
cmake --version
g++ --version
openssl version -a
```

Configure and build:

```bash
cmake -S . -B build -G Ninja -DBUILD_TESTING=ON
cmake --build build
```

---

## 6. Running the Test Suite

Run all registered CTest cases:

```powershell
ctest --test-dir build --output-on-failure
```

For Visual Studio multi-configuration builds:

```powershell
ctest --test-dir build -C Release --output-on-failure
```

Run tests for a specific lab:

```powershell
ctest --test-dir build -L Lab1 --output-on-failure
ctest --test-dir build -L Lab3 --output-on-failure
ctest --test-dir build -L Lab4 --output-on-failure
ctest --test-dir build -L Lab5 --output-on-failure
ctest --test-dir build -L Lab6 --output-on-failure
```

Expected result:

```text
100% tests passed, 0 tests failed
```

The project currently includes automated KAT, correctness, negative, misuse, and malformed-input checks for Labs 1, 3, 4, 5, and 6.

---

## 7. Command-Line Examples

Executable paths may be:

```text
build/Lab1
build/Lab3
build/Lab4
build/Lab5
build/Lab6
```

On Windows, append `.exe`.

Run an executable without arguments to display its complete usage information.

### Lab 1

Generate an AES-256 key:

```powershell
.\build\Lab1.exe keygen --bits 256 --out aes.key
```

Encrypt using AES-GCM:

```powershell
.\build\Lab1.exe encrypt --mode gcm --key aes.key --text "Hello world" --out ciphertext.bin
```

Decrypt:

```powershell
.\build\Lab1.exe decrypt --mode gcm --key aes.key --in ciphertext.bin --out plaintext.txt
```

Run the known-answer tests and self-tests:

```powershell
.\build\Lab1.exe kat
.\build\Lab1.exe selftest
```

### Lab 3

Generate an RSA-3072 key pair:

```powershell
.\build\Lab3.exe keygen --bits 3072 --pub public.pem --priv private.pem
```

Encrypt:

```powershell
.\build\Lab3.exe encrypt --pub public.pem --in message.bin --out ciphertext.bin
```

Decrypt:

```powershell
.\build\Lab3.exe decrypt --priv private.pem --in ciphertext.bin --out recovered.bin
```

Run the automated test suite:

```powershell
.\build\Lab3.exe selftest
```

### Lab 4

Hash a file with SHA-256:

```powershell
.\build\Lab4.exe hash --algo sha256 --in message.bin
```

Generate SHAKE256 output:

```powershell
.\build\Lab4.exe hash --algo shake256 --outlen 64 --in message.bin
```

Run KAT and self-test suites:

```powershell
.\build\Lab4.exe kat
.\build\Lab4.exe selftest
```

The self-test includes a controlled SHA-256 length-extension demonstration using a naive secret-prefix MAC.

### Lab 5

Generate an ECDSA P-256 key pair:

```powershell
.\build\Lab5.exe keygen --algo ecdsa-p256 --pub ecdsa_pub.pem --priv ecdsa_priv.pem
```

Sign:

```powershell
.\build\Lab5.exe sign --algo ecdsa-p256 --in message.bin --out signature.bin --priv ecdsa_priv.pem --hash sha256
```

Verify:

```powershell
.\build\Lab5.exe verify --algo ecdsa-p256 --in message.bin --sig signature.bin --pub ecdsa_pub.pem
```

Run the automated tests:

```powershell
.\build\Lab5.exe selftest
```

### Lab 6

Generate an ML-DSA-44 key pair:

```powershell
.\build\Lab6.exe keygen --algo mldsa-44 --pub mldsa_pub.pem --priv mldsa_priv.pem
```

Sign and verify:

```powershell
.\build\Lab6.exe sign --algo mldsa-44 --in message.bin --out signature.bin --priv mldsa_priv.pem
.\build\Lab6.exe verify --algo mldsa-44 --in message.bin --sig signature.bin --pub mldsa_pub.pem
```

Generate an ML-KEM-512 key pair:

```powershell
.\build\Lab6.exe keygen --algo mlkem-512 --pub mlkem_pub.pem --priv mlkem_priv.pem
```

Run the automated tests:

```powershell
.\build\Lab6.exe selftest
```

---

## 8. Benchmarking

Each lab includes or is intended to include benchmarking commands for its required algorithms.

Benchmark reports should record:

- CPU model
- Core and thread count
- RAM
- Operating system
- Compiler and compiler flags
- Cryptographic-library version
- Input size
- Number of runs
- Mean
- Median
- Standard deviation
- 95% confidence interval
- Throughput or operations per second

Recommended output directory:

```text
results/
├── lab1_windows.csv
├── lab1_linux.csv
├── lab3_windows.csv
├── lab3_linux.csv
├── lab4_windows.csv
├── lab4_linux.csv
├── lab5_windows.csv
├── lab5_linux.csv
├── lab6_windows.csv
└── lab6_linux.csv
```

---

## 9. Security Notes

- Test keys and secrets in this repository are for laboratory use only.
- ECB mode is insecure for structured or repeated plaintext.
- CTR, CCM, and GCM nonces must not be reused with the same key.
- Authentication failures must terminate decryption without returning plaintext.
- RSA encryption uses OAEP with SHA-256 rather than PKCS#1 v1.5 encryption.
- Large data is encrypted using AES-256-GCM with an RSA-OAEP-wrapped AES key.
- Raw `SHA256(key || message)` is not a secure MAC construction.
- HMAC-SHA256 should be used instead of a naive secret-prefix hash.
- Signature verification must reject modified data, signatures, and public keys.
- ML-KEM decapsulation must be treated carefully because invalid ciphertext can produce an unrelated shared secret instead of a conventional parse error.

---

## 10. Known Limitations

- Lab 6 depends on OpenSSL builds that expose the required ML-DSA and ML-KEM algorithms.
- Cross-platform behavior depends on the available OpenSSL provider configuration.
- The minimal PQ certificate format is an educational structure and is not a replacement for production X.509 or standardized PQ certificate profiles.
- Attack demonstrations are restricted to offline test data owned by the student.
- Benchmark results vary by CPU, compiler, operating system, provider implementation, and hardware acceleration.

---

## 11. Academic Integrity and Ethics

This project is intended solely for defensive education and controlled laboratory use.

- All attack demonstrations must use local test artifacts.
- No third-party system, live service, or unauthorized data may be targeted.
- External libraries, standards, test vectors, and references must be cited in the final report.
- AI-assisted development or debugging should be disclosed according to the course policy.
- Keys and secrets stored in the repository are test values only and must never be reused in production.

---

## 12. Clean Build Verification

Before submission, perform a clean build:

```powershell
Remove-Item -Recurse -Force build
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Ubuntu:

```bash
rm -rf build
cmake -S . -B build -G Ninja -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

A successful clean build and a fully passing CTest run should be recorded in the final report.
