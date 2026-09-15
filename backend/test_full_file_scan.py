import unittest
import os
import tempfile
from unittest.mock import patch
from app.services.malware_service import MalwareDetectionService

class TestFullFileScan(unittest.TestCase):
    def setUp(self):
        self.test_file = tempfile.NamedTemporaryFile(delete=False)
        self.test_file.write(b"Safe text content")
        self.test_file.close()

    def tearDown(self):
        os.remove(self.test_file.name)

    @patch('app.services.malware_service.MalwareDetectionService.predict', return_value=0.1)
    def test_clean_file(self, mock_predict):
        # We mock pyclamd connection failure or success based on environment.
        # Let's test the graceful fallback or the actual integration.
        with patch('pyclamd.ClamdNetworkSocket') as mock_clamd:
            mock_instance = mock_clamd.return_value
            mock_instance.ping.return_value = True
            mock_instance.scan_file.return_value = None # Clean
            
            result = MalwareDetectionService.scan_full_file(self.test_file.name, "test.txt")
            self.assertEqual(result["verdict"], "CLEAN")
            self.assertEqual(result["full_file_scanned"], True)
            self.assertEqual(result["scan_complete"], True)

    @patch('app.services.malware_service.MalwareDetectionService.predict', return_value=0.1)
    def test_malicious_file(self, mock_predict):
        with patch('pyclamd.ClamdNetworkSocket') as mock_clamd:
            mock_instance = mock_clamd.return_value
            mock_instance.ping.return_value = True
            abs_path = os.path.abspath(self.test_file.name)
            mock_instance.scan_file.return_value = {abs_path: ("FOUND", "EICAR-Test-Signature")}
            
            result = MalwareDetectionService.scan_full_file(self.test_file.name, "malware.exe")
            self.assertEqual(result["verdict"], "MALICIOUS")
            self.assertEqual(result["clamav_result"], "EICAR-Test-Signature")

    @patch('app.services.malware_service.MalwareDetectionService.predict', return_value=0.1)
    def test_clamav_unreachable_fail_closed(self, mock_predict):
        with patch('pyclamd.ClamdNetworkSocket') as mock_clamd:
            mock_instance = mock_clamd.return_value
            mock_instance.ping.return_value = False # Unreachable
            
            os.environ["MALWARE_SCAN_FAIL_CLOSED"] = "true"
            result = MalwareDetectionService.scan_full_file(self.test_file.name, "test.txt")
            self.assertEqual(result["verdict"], "SCAN_FAILED")

if __name__ == '__main__':
    unittest.main()
