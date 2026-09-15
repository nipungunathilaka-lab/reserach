import ctypes
import ctypes.util
import logging
import platform

logger = logging.getLogger(__name__)

_sodium = None
_oqs = None

def _load_native_libs():
    global _sodium, _oqs
    
    # Try libsodium
    sodium_path = ctypes.util.find_library('sodium')
    if sodium_path:
        try:
            _sodium = ctypes.cdll.LoadLibrary(sodium_path)
            # Setup signatures
            _sodium.sodium_memzero.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            _sodium.sodium_mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            _sodium.sodium_mlock.restype = ctypes.c_int
            _sodium.sodium_munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            _sodium.sodium_munlock.restype = ctypes.c_int
        except OSError:
            _sodium = None
            
    # Try liboqs as fallback for cleanse
    oqs_path = ctypes.util.find_library('oqs')
    if oqs_path:
        try:
            _oqs = ctypes.cdll.LoadLibrary(oqs_path)
            _oqs.OQS_MEM_cleanse.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        except OSError:
            _oqs = None

_load_native_libs()

class SecureBuffer:
    """
    A cryptographically secure buffer that supports native memory zeroization
    via libsodium or liboqs, and optionally locks memory to prevent swapping.
    It can be used as a context manager to ensure safe cleanup.
    """
    def __init__(self, size_or_bytes):
        self._wiped = False
        self._locked = False
        
        if isinstance(size_or_bytes, int):
            self._size = size_or_bytes
            self._buf = bytearray(self._size)
        elif isinstance(size_or_bytes, (bytes, bytearray)):
            self._size = len(size_or_bytes)
            self._buf = bytearray(size_or_bytes)
        else:
            raise TypeError("Expected int or bytes-like object")
            
        # Get native pointer. We use a ctypes char array over the bytearray to get the address
        self._c_buf = (ctypes.c_char * self._size).from_buffer(self._buf)
        self._ptr = ctypes.addressof(self._c_buf)
        
        self._lock_memory()

    def _lock_memory(self):
        if _sodium and hasattr(_sodium, 'sodium_mlock'):
            res = _sodium.sodium_mlock(self._ptr, self._size)
            if res == 0:
                self._locked = True
            else:
                logger.debug("sodium_mlock failed (likely due to ulimit), continuing unlocked but will still zeroize.")

    def _unlock_memory(self):
        if self._locked and _sodium and hasattr(_sodium, 'sodium_munlock'):
            _sodium.sodium_munlock(self._ptr, self._size)
            self._locked = False

    def wipe(self):
        if self._wiped:
            return
            
        if self._size > 0:
            if _sodium and hasattr(_sodium, 'sodium_memzero'):
                _sodium.sodium_memzero(self._ptr, self._size)
            elif _oqs and hasattr(_oqs, 'OQS_MEM_cleanse'):
                _oqs.OQS_MEM_cleanse(self._ptr, self._size)
            else:
                # Fallback to libc memset via ctypes if neither is available
                ctypes.memset(self._ptr, 0, self._size)
                
        self._unlock_memory()
        self._wiped = True
        logger.debug("Secure cryptographic buffer zeroization completed")
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.wipe()
        
    @property
    def memory(self):
        """Returns a writable memoryview of the buffer."""
        if self._wiped:
            raise RuntimeError("Accessing wiped memory")
        return memoryview(self._buf)

    @property
    def bytes(self):
        """
        Returns an immutable bytes copy. 
        WARNING: This creates a copy that Python garbage collector manages and cannot be explicitly zeroized.
        Avoid using this for highly sensitive material whenever possible.
        """
        if self._wiped:
            raise RuntimeError("Accessing wiped memory")
        return bytes(self._buf)
        
    def __del__(self):
        # Last resort fallback if context manager is not used
        if getattr(self, '_wiped', True):
            return
        self.wipe()
