import threading
import time
from typing import Dict, Optional, Tuple

class ARPMonitor:
    def __init__(self):
        self._trusted_macs: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._active = False
        
    def start(self):
        self._active = True
        
    def stop(self):
        self._active = False
        
    def check_arp_mapping(self, ip: str, mac: str) -> Tuple[bool, Optional[str]]:
        if not self._active:
            return False, None
            
        with self._lock:
            if ip in self._trusted_macs:
                expected_mac = self._trusted_macs[ip]
                if expected_mac != mac:
                    return True, expected_mac
            else:
                self._trusted_macs[ip] = mac
        return False, None

    def baseline_mapping(self, ip: str, mac: str):
        with self._lock:
            self._trusted_macs[ip] = mac

    def clear_baseline(self):
        with self._lock:
            self._trusted_macs.clear()

arp_monitor = ARPMonitor()
