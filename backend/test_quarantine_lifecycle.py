import unittest
import os
from unittest.mock import patch
from app.security.quarantine import QuarantineService
from app.database.db import init_db
from app.database.models import QuarantineItem, Base
from app.database.db import engine

class TestQuarantineLifecycle(unittest.TestCase):
    def setUp(self):
        init_db()

    def tearDown(self):
        Base.metadata.drop_all(bind=engine)
    
    @patch('app.security.quarantine.quarantine_storage.save_to_quarantine')
    def test_quarantine_flow(self, mock_save):
        item = QuarantineService.quarantine_file(
            user_id=1,
            original_filename="malware.exe",
            file_bytes=b"MALWARE_BYTES",
            detection_engine="ClamAV",
            reason="Malware Scan Failed",
            detection_name="EICAR-Test-Signature",
            malware_score=1.0,
            transfer_id="transfer_123"
        )
        self.assertIsNotNone(item.id)
        self.assertEqual(item.quarantine_status, "QUARANTINED")
        self.assertEqual(item.original_filename, "malware.exe")
        
        items = QuarantineService.get_quarantine_list()
        self.assertTrue(any(i.id == item.id for i in items))

        # Test Rescan (with mocked result)
        with patch('app.security.quarantine.quarantine_service.load_from_quarantine', return_value=b"MALWARE_BYTES"), \
             patch('app.services.malware_service.MalwareDetectionService.scan_full_file', return_value={"verdict": "MALICIOUS"}):
            rescan_res = QuarantineService.rescan_item(item.id, "admin")
            self.assertEqual(rescan_res["result"]["verdict"], "MALICIOUS")
            
        # Test Release (Denial because it's still malicious)
        with patch('app.security.quarantine.quarantine_service.load_from_quarantine', return_value=b"MALWARE_BYTES"), \
             patch('app.services.malware_service.MalwareDetectionService.scan_full_file', return_value={"verdict": "MALICIOUS"}):
            release_res = QuarantineService.release_item(item.id, "admin")
            self.assertIn("error", release_res)
            
        # Test Delete
        with patch('app.security.quarantine.quarantine_storage.delete_from_quarantine'):
            del_res = QuarantineService.delete_item(item.id, "admin")
            self.assertEqual(del_res["status"], "deleted")
            
        # Verify it's removed from active list
        items = QuarantineService.get_quarantine_list()
        self.assertFalse(any(i.id == item.id for i in items))

if __name__ == '__main__':
    unittest.main()
