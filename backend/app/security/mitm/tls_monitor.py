import ssl
import socket
from typing import Optional, Dict

class TLSMonitor:
    def __init__(self):
        self._trusted_fingerprints: Dict[str, str] = {}
        
    def set_trusted_fingerprint(self, domain_or_ip: str, fingerprint: str):
        self._trusted_fingerprints[domain_or_ip] = fingerprint
        
    def check_identity(self, domain_or_ip: str, current_fingerprint: str) -> bool:
        """Returns True if a mismatch is detected."""
        if domain_or_ip in self._trusted_fingerprints:
            return self._trusted_fingerprints[domain_or_ip] != current_fingerprint
        return False
        
    def get_server_fingerprint(self, host: str, port: int) -> Optional[str]:
        """Fetch server certificate fingerprint. Returns None if unreachable or not SSL."""
        # Simulated or best-effort TLS check for Python 3.10+
        # This is a passive check since actual TLS inspection is limited without proxying
        # In a real environment, we'd use OpenSSL or passive PCAP observation if possible.
        pass

tls_monitor = TLSMonitor()
