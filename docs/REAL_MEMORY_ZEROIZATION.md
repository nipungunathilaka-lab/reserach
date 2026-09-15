# REAL MEMORY ZEROIZATION IMPLEMENTATION

## 1. Original Problem
The system previously contained fake zeroization code (e.g. `logger.info("Wiping residual keys from RAM")`) that did not actually overwrite memory. Normal Python operations such as `del` or assigning `None` only decrement reference counts and invoke garbage collection, without securely erasing the underlying bytes from process memory. This left cryptographic keys vulnerable to extraction via core dumps, swap files, or process memory scraping.

## 2. Threat Addressed
This implementation addresses **Cold Boot Attacks**, **Process Memory Scraping**, **Swap Extraction**, and **Core Dump Leakage** by proactively overwriting cryptographic secrets in RAM the moment they are no longer required, minimizing their temporal footprint.

## 3. Why `del`, `None`, and Python GC are Insufficient
Python's garbage collector returns memory to the OS or internal pools but does not zero out the physical bytes. A forensic analysis of process memory could easily recover immutable Python `bytes` objects representing AES keys or ML-KEM private keys.

## 4. Native Zeroization Primitive Selected
- **Linux Environment (Docker)**: `libsodium` via `ctypes` bindings.
- **Primitives Used**: `sodium_memzero()`, `sodium_mlock()`, `sodium_munlock()`.
- **Fallback**: `liboqs` `OQS_MEM_cleanse()` or `ctypes.memset()` if `libsodium` is unavailable.

## 5. SecureBuffer Architecture
The new `SecureBuffer` class acts as a context manager wrapper around a pre-allocated native bytearray. 
- During `__init__`, it attempts to lock the memory using `sodium_mlock`.
- It exposes memory securely via `memoryview` to avoid implicit immutable copies.
- Upon `__exit__`, it immediately invokes `sodium_memzero` on the raw memory pointer, neutralizing the secret regardless of success or exception.

## 6. Secret Lifecycle
Secrets are instantiated directly into `SecureBuffer` contexts:
```python
with SecureBuffer(os.urandom(32)) as aes_key:
    # Use aes_key.memory for encryption operations
    ...
# Key is securely erased here
```

## 7. AES/PFCE Cleanup
Per-fragment AES-256 keys generated during PFCE engine transfers are placed into `SecureBuffer`s. After the fragment is encrypted and the key is protected (wrapped), the `SecureBuffer` context exits, securely wiping the raw fragment key before the next fragment begins.

## 8. ECDH Cleanup
The ephemeral shared secret generated during classical ECDH exchange is placed into a `SecureBuffer`. It is wiped immediately after deriving the key-wrapping key (which is itself in a `SecureBuffer` and wiped after use).

## 9. ML-KEM Cleanup
ML-KEM-768 secret keys and shared secrets decapsulated using `liboqs` are explicitly pushed into `SecureBuffer` instances. The application zeroes these buffers as soon as hybrid KDF processes complete. 

## 10. Hybrid-Secret Cleanup
The HKDF derivations from ML-KEM and ECDH shared secrets construct `pqc_kek` and `wrap_key`. Both are managed by `SecureBuffer` instances that are zeroized prior to application return.

## 11. Exception-Safe Cleanup
Using Python `try/finally` blocks and `with` context managers, the system guarantees that `sodium_memzero()` will execute even if network errors, malware rejections, AI policy violations, or HTTP exceptions interrupt the file transfer.

## 12. Memory Locking Behavior
Where supported by system `ulimit`, `SecureBuffer` uses `sodium_mlock` to pin the memory page containing the secret, preventing the OS from writing it to disk (swap/pagefile). If this fails, the buffer operates unlocked but will still perform secure zeroization.

## 13. Third-Party Library Limitations
- **PyCA Cryptography / liboqs-python**: These libraries may still briefly allocate internal buffers or intermediate OpenSSL cipher contexts. We ensure the *application-owned* input/output buffers are wiped. Python's `AESGCM` and `oqs` bindings securely dispose of their native contexts during standard garbage collection, but our explicit application memory overwrites eliminate the primary lingering copies.

## 14. Automated Validation Tests
`test_secure_memory.py` uses `ctypes.addressof()` to inspect the exact physical memory space allocated to keys, proving that the address contains the secret beforehand and `\x00` afterward. It explicitly proves use-after-wipe protection, exception safety, and end-to-end integration across CryptoService.

## 15. Exact Supported Security Claim
**"Application-managed cryptographic key and shared-secret buffers are explicitly zeroized immediately after their final use using native secure-memory primitives, including exception and failure paths."**
