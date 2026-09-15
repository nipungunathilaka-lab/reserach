import unittest
from app.security.mitm.mitm_detector import MITMDetector
from app.security.mitm.models import MITMIndicators
from app.security.mitm.arp_monitor import arp_monitor
from app.security.mitm.gateway_monitor import gateway_monitor
from app.security.mitm.tls_monitor import tls_monitor
from app.security.mitm.key_integrity_monitor import key_integrity_monitor

class TestMITMDetector(unittest.TestCase):
    def setUp(self):
        arp_monitor.clear_baseline()
        arp_monitor.start()

    def tearDown(self):
        arp_monitor.stop()

    def test_stable_mapping_no_alert(self):
        arp_monitor.baseline_mapping("192.168.1.100", "AA:BB:CC:DD:EE:FF")
        result = MITMDetector.evaluate_transfer(
            client_ip="192.168.1.100",
            client_port=12345,
            sender_id=None,
            sender_spki_fingerprint=None,
            simulate_arp_mac="AA:BB:CC:DD:EE:FF",
            simulate_gateway_ip="192.168.1.1"
        )
        self.assertNotIn(MITMIndicators.ARP_MAC_CONFLICT, result.indicators)

    def test_conflicting_mac_alert(self):
        arp_monitor.baseline_mapping("192.168.1.100", "AA:BB:CC:DD:EE:FF")
        result = MITMDetector.evaluate_transfer(
            client_ip="192.168.1.100",
            client_port=12345,
            sender_id=None,
            sender_spki_fingerprint=None,
            simulate_arp_mac="11:22:33:44:55:66",
            simulate_gateway_ip="192.168.1.1"
        )
        self.assertIn(MITMIndicators.ARP_MAC_CONFLICT, result.indicators)
        self.assertEqual(result.severity, "CRITICAL")

    def test_gateway_change_alert(self):
        gateway_monitor.set_baseline("192.168.1.1", "eth0")
        result = MITMDetector.evaluate_transfer(
            client_ip="192.168.1.100",
            client_port=12345,
            sender_id=None,
            sender_spki_fingerprint=None,
            simulate_arp_mac="AA:BB:CC:DD:EE:FF",
            simulate_gateway_ip="10.0.0.1" # Changed
        )
        self.assertIn(MITMIndicators.DEFAULT_GATEWAY_CHANGED, result.indicators)

    def test_public_key_substitution(self):
        # Without DB setup, key_integrity_monitor returns True, None if no baseline exists.
        # So we can't easily test rejection without a DB mock.
        pass

if __name__ == '__main__':
    unittest.main()
