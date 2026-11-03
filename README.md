# Secure File Exchange Platform

## Secure Digital Document Vault

### D1 — Understand Security

*Architecture, Trust Boundaries and Security Mapping*

*Course:* Cryptography  
*Professor:* Dra. Rocío Aldeco  
*Team:* Team 03  

*Team members:*
- Castro Delgado Daniela Beatriz - 319039414
- González Frías Ana Paula - 319285099 
- Hernández Rubio Dana Valeria - 317345153
- Murillo Rodríguez Sarah Sofia - 422130448
- Roque Ruiz Bruno Ezequiel - 318276588

*Date:* 26/09/2026

# 1. System Overview
## 1.1 What problem does the system solve?

The Secure File Exchange Platform (Secure Digital Document Vault) solves the problem of securely exchanging files between a sender (Alice) and one or more authorized recipients (Bob, Carol, etc.) over a channel or storage medium that is not trusted (public network, cloud, USB drive, shared folder, etc.).

The system assumes that the intermediate channel/storage can be observed, copied, modified, replaced, or tampered with by an attacker. Therefore, the file must be protected before it leaves the sender's environment and verified before it is accepted by the recipient.

## 1.2 Core features

- Encryption of the file content (AEAD) before it leaves the sender's trusted environment.
- Generation of a file key and individual protection of that key for each authorized recipient (hybrid encryption).
- Packaging of the encrypted file together with control metadata (recipient, version, timestamp, etc.).
- Digital signature of the package to guarantee sender authenticity.
- Signature and integrity verification on the recipient side before processing the package (fail-closed).
- Decryption and recovery of the original file only if all verifications succeed.
- Support for multiple authorized recipients per file.
- Local storage of private keys (keystore) on both ends.

## 1.3 What is explicitly out of scope (D1 stage)

- The choice of specific cryptographic algorithm (AEAD, hybrid scheme, signature, KDF) — to be defined in D2, D3, D5 and D6.
- Protection against a malicious sender: Alice is assumed to act in good faith.
- Compromise of the local endpoint/device (malware, physical access): out of scope for this project.
- Large-scale key management infrastructure (full PKI).
- Availability guarantees for the transfer channel (resilience against DoS).
- User interface / user experience design.

# 2. Architecture Diagram and Trust Boundaries
The diagram below shows the overall architecture of the system, identifying trusted components, untrusted components, trust boundaries, and the main data flows for the Alice → untrusted environment → Bob scenario.

![Secure File Exchange Platform Architecture](architecture-diagram.png)

**Trust boundary 1:** exit from Alice's zone.  
**Trust boundary 2:** entry into Bob/Carol's zone.

## 2.1 Component classification

| Category | Elements |
|---|---|
| **Trusted components** | Alice's original file; Alice's private signing key; protection module (AEAD encryption + packaging + signature); file key generation; recipients' public keys (used as input); signature/integrity verification at Bob's side; Bob's private key; file key recovery; AEAD decryption and verification; recovered file; fail-closed logic. |
| **Untrusted components / data** | The secure package once it leaves Alice's environment; the transfer channel or storage medium (network, disk, cloud, USB); the package as received by Bob (treated as untrusted input until verified). |
| **Trust boundaries** | Boundary 1: border between Alice's trusted zone and the untrusted environment. Boundary 2: border between the untrusted environment and Bob/Carol's trusted zone. |
| **External actors** | Alice (sender); Bob and Carol (authorized recipients); active/passive attacker able to observe, copy, modify, replace, replay, or corrupt the package. |

## 2.2 Where each cryptographic operation happens

- **Encryption:** inside the protection module, within Alice's trusted zone, before Boundary 1.
- **Signing:** also inside Alice's protection module, using her private key, before leaving her zone.
- **Signature/integrity verification:** in Bob's zone, immediately upon receiving the package (fail-closed if it fails).
- **Key storage:** private keys remain in local keystores; they never cross trust boundaries in plaintext.

## 2.3 Main data flows

1. File + Alice's private key → protection module.
2. Protection module → secure package generated (encrypted + signed).
3. The package crosses Boundary 1 toward the untrusted channel/storage.
4. The package crosses Boundary 2 and reaches Bob/Carol's environment.
5. Signature/integrity verification and file key recovery.
6. AEAD decryption and verification.
7. Recovery of the original file, or a secure rejection (fail-closed) if any verification fails.

# 3. Security Requirements
The following security requirements the system must guarantee are listed below, written as verifiable properties:

1. **Confidentiality of file content.**  
   An attacker who obtains the encrypted package from the untrusted channel must not be able to learn the file content without possessing the correct private key of an authorized recipient.

2. **Confidentiality of the file key.**  
   An attacker who intercepts the package must not be able to recover the key protecting the file without the legitimate recipient's private key.

3. **Integrity of file content.**  
   Any unauthorized modification of the encrypted content must be detectable by the recipient before the file is recovered or used.

4. **Authenticity of the sender.**  
   The recipient must be able to verify, through cryptographic evidence, that the package was actually generated by the sender it claims to come from.

5. **Integrity of metadata.**  
   Any unauthorized alteration of control metadata must be detected before it is trusted or used.

6. **Confidentiality of private keys.**  
   Alice's and Bob's private keys must remain protected even if the local storage where they reside is compromised (never stored in plaintext).

7. **Protection against package tampering.**  
   A package that has been modified or corrupted in transit must be securely rejected (fail-closed), without exposing its content.

8. **Access restricted to authorized recipients.**  
   Only the recipients explicitly designated by the sender at protection time will be able to recover the original file.

9. **Replay resistance.**  
   The system must be able to identify or handle a previously valid package that is resent by an attacker, according to the defined replay policy.

10. **No information disclosure on failure.**  
    When a verification fails, the system must not leak internal information that could help an attacker refine an attack.

# 4. Threat Model

## 4.1 Assets to protect

- File content.
- File key / file recovery material.
- Package metadata (name, timestamp, recipient identifier, version).
- Private keys (Alice's and Bob's).
- User credentials (keystore passwords).
- Validity of the digital signature / sender identity.
- List of authorized recipients.

## 4.2 Adversaries

- External attacker with access to the channel/storage.
- Malicious recipient attempting to use the system outside authorized boundaries.
- Attacker modifying metadata to alter the system's behavior.
- Attacker with temporary access to the device (physical or remote).

## 4.3 What the attacker can do

- Passive observation (eavesdropping) of all traffic/storage in the untrusted channel.
- Active modification of bits, blocks, or metadata in the package.
- Replacement/injection: substituting a legitimate package, injecting malformed packages, or replacing a public key.
- Replay of a previously valid package.
- Suppression/deletion of packages, affecting availability.
- Attempting to get the system to accept a fake public key (without physical access to the keystore).

## 4.4 What the attacker cannot do

- No execution or physical access to Alice's or Bob's local OS/hardware.
- Not assumed capable of breaking the underlying cryptographic primitives.

## 4.5 Mapping: Asset → Threat → Attack Scenario → Security Requirement → Design Constraint

| Asset | Threat | Attack scenario | Security requirement | Design constraint |
|---|---|---|---|---|
| *File content* | Disclosure | The attacker obtains the package from the channel and tries to read the content. | Only authorized recipients can access the content. | The file must be encrypted before leaving the trusted environment. |
| *File key* | Disclosure | The attacker intercepts the package and tries to obtain the key protecting the file. | Only authorized recipients can recover the key. | The file key must be individually protected per recipient. |
| *Package metadata* | Modification / Tampering | The attacker alters metadata in transit or storage. | Any unauthorized modification must be detected. | Metadata must be authenticated together with the content. |
| *Sender identity* | Spoofing | The attacker builds or modifies a package presenting it as coming from Alice. | The recipient must verify the real authenticity of the sender. | The package must include verifiable authenticity evidence. |
| *Package / channel* | Replay | The attacker resends an old, previously valid copy of the package. | The system must identify or discard repeated packages. | The package must include information that distinguishes each specific send. |
| *Private keys* | Theft or compromise | The attacker accesses local storage and tries to extract the private key. | Private keys must remain protected even if local storage is compromised. | Private keys must not be stored in plaintext. |
| *Complete secure package* | Manipulation / corruption | The attacker corrupts the package and the recipient processes it unaware. | Manipulated packages must be rejected (fail-closed). | The system must validate integrity before exposing the content. |
| *List of recipients* | Unauthorized access | A non-selected user attempts to recover the file. | Only designated recipients will be able to recover the file. | Recipient selection is fixed at protection time. |
| *User credentials* | Interception / sniffing | The attacker captures plaintext traffic during login. | Credentials must be protected in transit and at rest. | Use of encrypted protocols/storage, never plaintext. |

# 5. Trust Assumptions

## 5.1 Alice's zone (sender)
| Component | Trust level | Security assumption (justification) |
|---|---|---|
| **Alice (external actor)** | Trusted | Assumed to act in good faith and to only send to recipients of her choosing. The design does not protect against a malicious sender. |
| **Original file (plaintext)** | Partially trusted | Assumed valid before entering the protection module; its future confidentiality depends entirely on encryption being applied correctly. |
| **Alice's private key (signature)** | Trusted | Assumed that Alice's device adequately protects it. If this fails, an attacker could sign forged packages impersonating Alice. |
| **Protection module (AEAD + signature)** | Trusted | Assumed to be correctly implemented (correct primitives, unique nonces) and not modified by an attacker. |
| **File key generation** | Trusted | A cryptographically secure random number generator (CSPRNG) is assumed. If weak, the system's entire confidentiality would collapse. |
| **Recipients' public keys** | Partially trusted | Obtained from a channel external to the diagram; assumed to have been obtained authentically (verified out-of-band). If this fails, a MITM attack on key registration occurs. |
| **Secure package generated** | Trusted → Untrusted once crossing Boundary 1 | Its protection (encryption + signature) is the only thing upholding trust once it leaves the controlled environment. |

## 5.2 Untrusted zone (transfer / storage)
| Component | Trust level | Security assumption (justification) |
|---|---|---|
| **Transfer/storage channel** | Untrusted | By design, the attacker is assumed to have full control: observe, copy, modify, replace, replay, or delete the package. |
| **Attacker (active/passive)** | Adversary | Full access to the channel/storage is assumed, but not to Alice's or Bob's trust zones. |

## 5.3 Bob/Carol's zone (recipients)
| Component | Trust level | Security assumption (justification) |
|---|---|---|
| **Package received** | Untrusted until verified | Even if it arrives encrypted and signed, it is treated as hostile input until signature and integrity are validated. |
| **Signature/integrity verification** | Trusted | Assumed that this code is correct and has not been tampered with; it acts as the gatekeeper for the rest of the process. |
| **Bob's private key** | Trusted | Protected on his device, with no third-party access. |
| **File key recovery** | Trusted | Depends on Bob's private key being intact and the package having already passed verification. |
| **AEAD decryption and verification** | Trusted | Assumed to correctly detect any tampering with the ciphertext and to fail securely if authentication fails. |
| **Recovered original file** | Trusted (conditioned) | Trusted only if all preliminary checks were successful. |
| **Fail-closed** | Trusted | Assumed that this logic does not reveal sensitive information upon failure and correctly blocks unverified data. |

## 5.4 Cross-cutting assumption (outside the diagram, but critical)
| Component | Trust level | Security assumption (justification) |
|---|---|---|
| **Alice's and Bob's local environment (OS/hardware)** | Trusted, with an explicit caveat | Assumed that no local device is compromised. If the local machine were compromised, no cryptographic protection could prevent the private key or plaintext file from being leaked. |


# 6. Attack Surface Review
## 6. Attack Surface Review

The attack surface is organized according to the system's two trust boundaries.

### 6.1 Boundary 1 — Alice's environment → Untrusted channel

| Interface / component | What could go wrong? | Security property at risk |
| :--- | :--- | :--- |
| Secure package generated (output) | It is the only exposed surface when leaving the trusted environment; its cryptographic protection is the only thing preventing an observer from extracting information. | Confidentiality, integrity |
| Recipient public key import interface | If the public key is obtained via an unverified channel, an attacker can substitute it before encryption (MITM). | Confidentiality of content |
| Password entry | If the password unlocking Alice's keystore is captured (keylogging, unmasked field), the private key is compromised. | Confidentiality of private keys |
| CLI arguments | Paths, passwords, or keys passed as parameters may be exposed in shell history or process logs. | Confidentiality of credentials and keys |

### 6.2 Boundary 2 — Untrusted channel → Bob/Carol's environment

| Interface / component | What could go wrong? | Security property at risk |
| :--- | :--- | :--- |
| Secure package parser | Malformed fields, out-of-range sizes, unexpected data types, or unsupported algorithm versions. | Availability, integrity |
| Recovered file input | Malicious filenames or path traversal when writing the decrypted file to disk. | File system integrity |
| Control metadata | Recipient identifiers, algorithm ID, version, and timestamps modifiable prior to verification. | Integrity, authenticity |
| Key interfaces / local keystore | Access to Bob's keystore and password/PIN request to unlock his private key. | Confidentiality of private keys |
| Transport / buffer channel | Reading, modification, replacement, replay, or deletion of packets in transit or at rest. | Confidentiality, integrity, availability |
| Error handling and logging | Error messages or logs that could leak internal information without a generic fail-closed scheme. | Confidentiality of internal information |
| Password entry at Bob's side | Same as Alice: capturing the password compromises the private key. | Confidentiality of private keys |
| Signature verification | Implementation errors could accept invalid or forged signatures. | Authenticity |

### 6.3 Realistic attacker capabilities (summary)

* Passive observation: can read and copy all traffic/storage in the untrusted channel.
* Active modification: can alter packet bits/blocks and metadata.
* Replacement/injection: can substitute a legitimate package, inject malformed packages, or replace a public key.
* Replay: can capture a valid package and resend it later.
* Suppression/deletion: can block or delete packages, affecting availability.
* Out of scope: no physical/execution access to local devices, and no ability to break underlying cryptographic primitives.

# 7. Unresolved Security Questions
The following cryptographic design decisions are intentionally left open at this stage:

* Which AEAD algorithm will be used (AES-GCM vs. ChaCha20-Poly1305) and with what key size?
* Which hybrid encryption scheme will protect the file key per recipient (RSA-OAEP, ECIES, or other)?
* Which digital signature algorithm will be used (RSA-PSS, ECDSA, EdDSA) and exactly which fields will be signed?
* How will nonces/IVs be generated and managed, avoiding reuse?
* What serialization/canonicalization format will be used for metadata before signing?
* What KDF and parameters will protect private keys at rest (encrypted keystore)?
* What mechanism will detect/mitigate replay attacks (timestamps, nonces, counters)?
* How will the key lifecycle be managed (generation, identification, rotation, revocation)?
* What minimal error information will be exposed without leaking details useful to an attacker?

### D2 - Cryptographic Implementation

### Overview

During the D2 development phase, the Secure Digital Document Vault
project implements authenticated encryption and decryption of digital
documents using AES-256-GCM.

The objective of this phase is to protect the confidentiality and
integrity of digital files while ensuring that unauthorized
modifications can be detected during decryption.

The implementation was developed in Python using the cryptography
library and validated through automated tests using pytest.

# 1. Encryption Design

### 1.1 Selected AEAD Algorithm

The selected algorithm is AES-256-GCM (Advanced Encryption Standard
in Galois/Counter Mode), an Authenticated Encryption with Associated
Data (AEAD) algorithm.

AES-256-GCM provides:

- *Confidentiality:* Protects the content of digital documents
  through symmetric encryption.
- *Integrity:* Detects unauthorized modifications to encrypted data.
- *Authentication:* Verifies that encrypted data and associated
  metadata have not been modified without authorization.

The implementation uses the AESGCM class provided by Python's
cryptography library.

### 1.2 Key Size and Generation

The system uses 256-bit (32-byte) symmetric encryption keys.

A new random encryption key is generated for each encryption
operation using:

python
key = AESGCM.generate_key(bit_length=256)


This approach avoids using a fixed encryption key for all
documents.

For the current prototype, encryption keys are stored separately
in local .key files.

These files are excluded from Git version control and must not
be published or shared with unauthorized users.

### 1.3 Nonce Strategy

Each encryption operation generates a random 96-bit (12-byte)
nonce using:

python
nonce = os.urandom(12)


The nonce is stored in the encrypted container because it is
required during decryption and does not need to remain secret.

AES-GCM requires that the same nonce must not be reused with
the same encryption key.

To reduce the risk of nonce reuse, the application generates
a new encryption key and a random nonce for every operation.

### 1.4 Metadata Authentication Strategy

The application uses Additional Authenticated Data (AAD)
to protect the integrity of file metadata.

The authenticated metadata includes:

- filename: Original filename.
- algorithm: Encryption algorithm used.
- version: Version of the encrypted container format.
- created_at: Date and time of encryption.

Before encryption, the metadata is serialized into JSON
using sorted keys:

python
aad = json.dumps(metadata, sort_keys=True).encode("utf-8")


The resulting AAD is supplied to AES-GCM during encryption
and must match during decryption.

Although the metadata remains readable, any unauthorized
modification causes authentication to fail.

### 1.5 Encrypted File Format

The encrypted document is stored in a JSON-based container
with the .vault extension.

The container includes:

- Authenticated file metadata.
- The encryption nonce.
- The ciphertext, including the AES-GCM authentication tag.

Example structure:

json
{
    "metadata": {
        "filename": "documento.txt",
        "algorithm": "AES-256-GCM",
        "version": 1,
        "created_at": "2026-10-16T12:00:00+00:00"
    },
    "nonce": "<hex-encoded nonce>",
    "ciphertext": "<hex-encoded ciphertext and authentication tag>"
}


The encryption key is not included in the .vault container.

# 2. Security Decisions

### 2.1 Why AEAD Instead of Encryption + Hash?

AEAD was selected because it combines encryption and
authentication within a single cryptographic construction.

Using encryption with a conventional hash does not provide
equivalent protection, since an attacker who modifies the
ciphertext could also calculate a new hash.

AES-256-GCM generates an authentication tag that depends on
the encryption key, nonce, ciphertext, and associated data.

This allows the application to detect unauthorized modifications
without requiring a separate authentication mechanism.

Although encryption combined with a properly implemented
Message Authentication Code (MAC) can also provide secure
authenticated encryption, AEAD simplifies implementation
and reduces the risk of cryptographic design errors.

### 2.2 What Happens if a Nonce Repeats?

Reusing the same nonce with the same AES-GCM encryption key
can seriously compromise security.

Nonce reuse can:

- Reveal relationships between encrypted plaintexts.
- Compromise confidentiality.
- Facilitate authentication forgery attacks.
- Allow attackers to exploit weaknesses caused by repeated
  encryption parameters.

To reduce this risk, the application generates a new
256-bit encryption key and a random 96-bit nonce for
every encryption operation.

### 2.3 What Attacker Are We Defending Against?

The system is designed to defend against an attacker who
can access, copy, intercept, or modify encrypted files,
but does not possess the corresponding secret encryption key.

The attacker may attempt to:

- Read confidential information from encrypted documents.
- Modify encrypted content.
- Alter authenticated metadata.
- Replace encrypted data with manipulated information.
- Decrypt documents using an incorrect key.

AES-256-GCM protects the confidentiality of encrypted
documents and detects unauthorized modifications during
authenticated decryption.

However, the current prototype does not protect against
attackers who obtain the secret encryption key or compromise
the computer where plaintext files and keys are stored.

The system also does not prevent deletion of encrypted files
or replacement of a complete valid encrypted container
with another valid container and its corresponding key.

# 3. Implementation

The cryptographic implementation is organized into separate
Python modules.

| File | Description |
|------|-------------|
| D2/src/encryption.py | Implements AES-256-GCM encryption, key generation, nonce generation, and metadata authentication. |
| D2/src/decryption.py | Implements authenticated decryption and authentication failure handling. |
| D2/main.py | Demonstrates the encryption and decryption workflow. |
| D2/requirements.txt | Defines the required Python dependencies. |

During encryption, the application generates a new key and
nonce, encrypts the document, and creates a .vault container.

During decryption, the application verifies the AES-GCM
authentication tag before writing the recovered plaintext.

If authentication fails, the operation is rejected and
no decrypted output file is generated.

# 4. Automated Tests

The implementation includes five automated tests developed
using pytest.

| Test | Objective | Expected Result |
|------|-----------|-----------------|
| Successful encryption and decryption | Verify that the original file can be recovered. | Recovered content matches the original. |
| Incorrect encryption key | Verify rejection of invalid keys. | Authentication fails. |
| Modified ciphertext | Verify detection of altered encrypted content. | Decryption is rejected. |
| Modified metadata | Verify integrity protection through AAD. | Authentication fails. |
| Multiple encryptions | Verify that repeated encryption produces different outputs. | Different ciphertexts, nonces, and keys. |

All five tests passed successfully during development.

To execute the tests, navigate to the D2 directory and run:

bash
python -m pytest -v -s


Expected result:

text
================ 5 passed ================


# 5. Security Limitations

The current implementation is an educational prototype.

Its main limitations include:

- Encryption keys are stored in local unencrypted .key files.
- No centralized key management system is implemented.
- User authentication and authorization are not implemented.
- Plaintext files are not securely erased after encryption.
- The system does not implement secure key backup or recovery.
- The implementation has not undergone an independent
  security audit.

A production version should incorporate secure key storage,
access control, and additional security mechanisms.

# 6. Development and Collaboration

The D2 implementation was developed collaboratively using
Git and GitHub.

The team organized its work into separate development branches
and integrated contributions through Pull Requests.

| Team Member | Contribution |
|-------------|--------------|
| Daniela | AES-256-GCM encryption module. |
| Ana Paula | Authenticated decryption module. |
| Sarah | Basic encryption and decryption tests. |
| Dana | Ciphertext and metadata integrity tests. |
| Bruno | Multiple encryption test. |

### D3 Hybrid Encryption 

# 1. Hybrid Design Explanation

## Why hybrid encryption is used

Public key cryptography (such as ECIES-secp256k1) is computationally intensive and not designed for encrypting large payloads directly. Conversely, symmetric encryption algorithms like AES-256-GCM are extremely fast and efficient at processing arbitrarily large files. Hybrid encryption combines the strengths of both paradigms: symmetric encryption encrypts the actual document payload using a randomly generated AES key, while asymmetric encryption securely transmits and shares this AES key with target recipients.

## Why symmetric encryption is still needed

Symmetric encryption provides high-throughput data processing and authenticated confidentiality (AEAD) for the document content itself. Without symmetric encryption, encrypting large documents with public-key algorithms would result in unacceptable performance overhead, strict size limitations, and severe computational inefficiency.

## Why per-recipient key encryption is required

Per-recipient key encryption enables secure multi-recipient document sharing without needing to duplicate or separately encrypt the main document payload for each user. A single file encryption key (FEK/AES key) encrypts the document payload once. That FEK is then encrypted separately using each authorized recipient's public key (ECIES), allowing each authorized user to unwrap the same underlying AES key using their private key.

# 2. Security Decisions

## How do recipients identify their key?

Each recipient entry inside the vault container contains a unique identifier (id). This id is computed as the deterministic SHA-256 fingerprint of the recipient's compressed public key (get_key_fingerprint). Upon opening a container, a recipient computes the SHA-256 fingerprint of their public key and searches the recipients list for a matching id to locate their encrypted AES key.

## What happens if an attacker modifies the recipient list?

The entire list of recipients (including IDs and encrypted keys) is serialized deterministically into the Authenticated Additional Data (AAD) bound to the AES-GCM ciphertext. If an attacker tampers with, adds, or removes any recipient or encrypted key entry, the reconstructed AAD during decryption will not match the tag computed at encryption time. Consequently, AES-GCM authentication fails immediately with an InvalidTag exception, preventing tampered containers from being decrypted.

## What happens if the public key is wrong?

If an invalid or corrupted public key is provided during encryption:

Format validation checks fail (e.g., verifying 33-byte length and valid compressed SECP256k1 prefix 0x02 or 0x03).

If an unauthorized recipient's key is used, their private key will fail to recover the correct AES key during ECIES decryption, raising an exception during key unwrapping or triggering an authentication failure (InvalidTag) when attempting to decrypt the file payload.

# 3. GitHub Requirements & Deliverables

Our repository fulfills all project requirements for Deliverable D3:

Inclusion of New Functionalities: Implementation of multi-recipient ECIES key management (src/key_management.py), canonical container handling with AAD integrity (src/container.py), AES-GCM file encryption (src/encryption.py), and multi-recipient file decryption (src/decryption.py).

Pull Request & Code Review: Changes introduced via Pull Request workflow on GitHub, including peer code reviews and discussion threads prior to merging into main.

Unit Tests & Continuous Integration: Comprehensive test suite with 100% test coverage across 7 test files (test_basic.py, test_container.py, test_decryption.py, test_encryption.py, test_key_management.py, test_multiple_encryptions.py, test_security.py). Automated test execution is configured using GitHub Actions (.github/workflows/python-tests.yml).

Updated README: Complete documentation outlining project structure, architecture decisions, threat model defenses, and usage instructions.
---

# D3 – Final Integration, Implementation, and Security Validation

> **Documentation note:** This section describes the integrated D3 checkpoint. Earlier D1 and D2 sections are preserved as evidence of the project's development and may describe earlier implementations.

## 1. Integration Overview

Secure Digital Document Vault combines **AES-256-GCM** for document encryption with **ECIES (secp256k1)** for protecting the file key for multiple recipients. A document is encrypted **once**, while its randomly generated AES key is encrypted separately for each authorized recipient.

The integrated Python implementation supports encrypted `.vault` containers, recipient identification, authenticated metadata, authorized decryption, rejection of unauthorized users, and detection of ciphertext tampering.

## 2. Project Modules

The main implementation is located in `D2/src/`:

| Module | Responsibility |
| --- | --- |
| `encryption.py` | Generates a fresh AES-256 key and 96-bit nonce, encrypts the file using AES-GCM, wraps the file key for each recipient, and creates the encrypted container. |
| `key_management.py` | Generates secp256k1 key pairs, calculates SHA-256 public-key fingerprints, and encrypts/decrypts file keys with ECIES. |
| `container.py` | Serializes, reads, and validates the JSON-based `.vault` container and constructs the authenticated metadata representation. |
| `decryption.py` | Validates the container, identifies the authorized recipient, unwraps the AES key, authenticates and decrypts the document, and checks output handling. |

### Key Formats

- AES file key: **256 bits (32 bytes)**, generated anew for each encrypted file.
- AES-GCM nonce: **96 bits (12 bytes)**, generated randomly for each encryption.
- ECIES private key: **32 bytes**.
- Compressed secp256k1 public key: **33 bytes**.
- Recipient identifier: **SHA-256 fingerprint**, represented as **64 hexadecimal characters**.

Each recipient has their own public/private key pair. Private keys are **not stored** in the `.vault` container.

## 3. Encryption Workflow

1. The sender selects a local document and at least two distinct authorized recipients.
2. The application generates a fresh random 256-bit AES file key and a 96-bit nonce.
3. It prepares the document metadata and full recipient list as **Additional Authenticated Data (AAD)**.
4. It encrypts the document **once** with **AES-256-GCM**.
5. It encrypts the same AES file key separately using each recipient's ECIES public key.
6. It stores metadata, recipient identifiers and wrapped keys, nonce, and ciphertext in a `.vault` file.

```text
Original document
       |
       v
Fresh AES-256 key + 96-bit nonce
       |
       v
AES-256-GCM encryption <--- authenticated metadata + recipient list (AAD)
       |
       +-------------------+
       |                   |
       v                   v
ECIES for Alice       ECIES for Bob
(public key)          (public key)
       |                   |
       +---------+---------+
                 |
                 v
        Encrypted .vault file
```

**Why hybrid encryption?** AES efficiently encrypts the document, while ECIES allows each recipient to recover the same AES key with their own private key. The document does not need to be encrypted again for every recipient.

## 4. Decryption Workflow

1. The recipient opens the `.vault` file, and the application validates its structure.
2. The application identifies the recipient using the fingerprint associated with their private key.
3. It locates the corresponding encrypted AES file key in the recipient list.
4. ECIES recovers the AES key using the recipient's private key.
5. The application reconstructs the AAD and attempts AES-GCM authenticated decryption.
6. If authentication succeeds, the original file is written to the output location. Otherwise, the operation is rejected.

An unauthorized recipient cannot select a matching wrapped key. Changes to authenticated ciphertext, metadata, or recipient information cause AES-GCM authentication to fail.

## 5. Encrypted `.vault` Container

The `.vault` file is a JSON-based container. The following is an **illustrative example**, not a literal generated file:

```json
{
  "metadata": {
    "filename": "confidential_document.txt",
    "algorithm": "AES-256-GCM",
    "key_encryption": "ECIES-secp256k1",
    "version": "1.0",
    "created_at": "example_timestamp"
  },
  "recipients": [
    {
      "id": "alice_public_key_fingerprint",
      "encrypted_key": "encrypted_AES_key_for_Alice"
    },
    {
      "id": "bob_public_key_fingerprint",
      "encrypted_key": "encrypted_AES_key_for_Bob"
    }
  ],
  "nonce": "encoded_nonce",
  "ciphertext": "encoded_ciphertext"
}
```

| Field | Purpose |
| --- | --- |
| `metadata` | Document name, algorithms, version, and creation information. |
| `recipients` | Authorized public-key fingerprints and an ECIES-encrypted AES key for each recipient. |
| `nonce` | Non-secret nonce required for AES-GCM decryption. |
| `ciphertext` | Encrypted document data with AES-GCM authentication information. |

The container does **not** include plaintext document content, plaintext AES file keys, or recipients' private keys.

## 6. Security Decisions

- **AES-256-GCM (AEAD):** Protects confidentiality and detects modifications to authenticated data.
- **ECIES with secp256k1:** Protects the file key independently for each recipient.
- **SHA-256 fingerprints:** Identify recipient public keys; fingerprints are identifiers, not secrets.
- **AAD:** Authenticates metadata and the complete recipient list without encrypting those fields.
- **Fresh key and nonce:** Each encrypted file receives a new AES key and random nonce; a nonce must never be reused with the same AES key.
- **Private-key separation:** Private keys remain outside the shared `.vault` file.

**Security scope:** AES-GCM authentication is not a digital signature and does not establish the sender's identity. Digital signature generation and verification are **not implemented** in the current D3 modules.

## 7. Automated Testing with PyTest

The team validated the integrated project with **42 passing automated tests locally**. The suite covers encryption/decryption, key management, fingerprints, multi-recipient behavior, invalid inputs, container validation, and tampering detection.

From the `D2` directory, run:

```bash
python -m pytest tests/ -v
```

The reported **42 passing tests** are a local result; a separate GitHub Actions run must be checked independently. Passing tests demonstrate expected behavior in tested cases, not the absence of all vulnerabilities.

## 8. GitHub Actions

The repository includes a **GitHub Actions workflow configured for automated testing**. Its purpose is to run the project's tests during the development and integration process.

```text
Code changes → GitHub Actions → PyTest → Test results
```

To inspect actual workflow runs, open the repository's **Actions** tab and review the relevant run and logs. Do not assume that the latest CI run passed solely because local tests passed.

## 9. D3 Demonstration

The script `D2/demo_d3.py` runs four scenarios using the integrated modules. It generates key pairs for **Alice** and **Bob** (authorized recipients) and **Charlie** (unauthorized).

| Scenario | Operation | Expected result |
| --- | --- | --- |
| 1. Encryption and decryption | Encrypt a sample document and decrypt it as Alice. | Recovered bytes match the original. |
| 2. Authorized sharing | Bob decrypts the **same** `.vault` file with his own private key. | Successful recovery. |
| 3. Unauthorized access | Charlie attempts to decrypt the file. | Rejected; no Charlie output file. |
| 4. Tampering detection | Modify a copy of the ciphertext and try to decrypt it. | Authentication fails; no recovered output. |

Run from `D2/`:

```bash
python demo_d3.py
```

Press **Enter** to advance between scenarios. When the checks pass, the final summary is:

```text
[PASS] Encryption and decryption
[PASS] Authorized sharing
[PASS] Unauthorized access rejected
[PASS] Modified document rejected

ALL 4 SECURITY SCENARIOS PASSED
```

Error messages during scenarios 3 and 4 are **expected rejection outcomes**, not unexpected failures.

### Generated Demonstration Files

The script saves its outputs in `D2/demo_files/`:

```text
D2/
├── src/
├── tests/
├── demo_d3.py
└── demo_files/
    ├── confidential_document.txt
    ├── confidential_document.vault
    ├── alice_decrypted.txt
    ├── bob_decrypted.txt
    └── modified_document.vault
```

The script removes known outputs from previous demonstrations before creating new ones. Files are kept after execution for inspection. `charlie_decrypted.txt` and `tampered_decrypted.txt` should **not** be created.

To exclude generated files from Git, add this line to the **repository root** `.gitignore`:

```gitignore
D2/demo_files/
```

The demonstration uses fictional data and generates fresh recipient keys each time; it does not implement persistent key storage.

## 10. Current Limitations

- **Digital signatures:** Proposed in D1, but not yet implemented in the current D3 code.
- **Persistent private-key management:** Secure storage, backup, and recovery are outside the current demonstration.
- **Graphical interface:** The current implementation uses Python modules and a command-line demonstration.
- **File transport:** `.vault` files can be transferred externally, but no dedicated cloud or network-sharing service is implemented.
- **Replay and deletion:** AES-GCM detects authenticated modifications but does not, by itself, prevent replay of an older valid container or deletion of files.

## 11. Team Contributions

| Team member | Main contribution |
| --- | --- |
| Daniela | AES-256-GCM encryption and multi-recipient integration (`encryption.py`). |
| Dana | ECIES key management and SHA-256 fingerprints (`key_management.py`). |
| Sarah | `.vault` container serialization and validation (`container.py`). |
| Ana Paula | Authorized decryption and authentication checks (`decryption.py`). |
| Bruno | GitHub Actions automated testing workflow and project documentation. |

The team integrated contributions using GitHub branches and Pull Requests.

## 12. Integration Results and Conclusion

The integrated D3 checkpoint combines AES-256-GCM encryption, ECIES-based key protection, multi-recipient access, and a structured `.vault` container. **42 automated tests passed locally**, and the four demonstration scenarios were successfully verified: authorized encryption/decryption, second-recipient access, unauthorized-user rejection, and ciphertext tampering detection.

These results support the functionality of the tested D2 and D3 components. The project remains a **development checkpoint**, with future work including persistent key management, digital signatures, a user interface, and dedicated secure file sharing.
