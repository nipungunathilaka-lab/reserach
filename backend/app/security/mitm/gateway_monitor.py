import threading
import socket
from typing import Optional, Tuple

class GatewayMonitor:
    def __init__(self):
        self._baseline_gateway_ip: Optional[str] = None
        self._baseline_interface: Optional[str] = None
        self._lock = threading.Lock()
        
    def set_baseline(self, gateway_ip: str, interface: str):
        with self._lock:
            self._baseline_gateway_ip = gateway_ip
            self._baseline_interface = interface
            
    def check_gateway(self, current_gateway_ip: str, current_interface: str) -> bool:
        """Returns True if an unexpected gateway change is detected."""
        with self._lock:
            if not self._baseline_gateway_ip:
                self._baseline_gateway_ip = current_gateway_ip
                self._baseline_interface = current_interface
                return False
                
            if self._baseline_gateway_ip != current_gateway_ip or self._baseline_interface != current_interface:
                return True
                
        return False

gateway_monitor = GatewayMonitor()
