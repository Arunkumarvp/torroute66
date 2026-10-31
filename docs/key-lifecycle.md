# PQVeil Mobile – Key Lifecycle & Backend Abstraction

## 1. Dual Backend Architecture
PQVeil Mobile abstracts key management through the `SecureKeyBackend` interface, allowing the mobile application to support both standard consumer Android devices and the research TrustZone environment.

```
                      ┌────────────────────────┐
                      │    SecureKeyBackend    │
                      │  (Rust Trait / JNI)    │
                      └───────────┬────────────┘
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
┌──────────────────────────────┐        ┌──────────────────────────────┐
│       Android Backend        │        │        OP-TEE Backend        │
│  - Android Keystore AES Key  │        │  - OP-TEE TA                 │
│  - StrongBox / TEE wrapping  │        │  - Sealed seeds in RPMB      │
│  - Encrypted seed on disk    │        │  - Seeds never leave HW      │
│  - Target: Real Android HW   │        │  - Target: QEMU / Board      │
└──────────────────────────────┘        └──────────────────────────────┘
```

## 2. Seed-Based Key Storage
Rather than persistently storing expanded post-quantum keys (which require 4,032 bytes for ML-DSA-65 secret keys and 2,400 bytes for ML-KEM-768 secret keys):
- Only a **32-byte seed** is stored for ML-DSA-65.
- Only a **64-byte seed** is stored for ML-KEM-768.
- Keys are expanded deterministically in memory only for the duration of the signing or decapsulation operation, and then immediately wiped (`zeroize`).

## 3. Lifecycle States
1. **Unprovisioned:** Device contains no identity keys.
2. **Provisioning (One-Time):**
   - High-entropy seeds generated via hardware RNG (`SecureRandom` on Android, `TEE_GenerateRandom` in OP-TEE).
   - Public keys derived and registered with the gateway / pinned trust anchor.
   - Private seeds sealed to hardware storage.
3. **Active:**
   - On each session handshake, the backend signs the transcript without exposing the private seed to JNI or UI layers.
4. **Invalidated / Destroyed:**
   - User initiates "Reset Identity" or device factory resets.
   - Wrapped seeds deleted; wrapping key purged from Keystore.

