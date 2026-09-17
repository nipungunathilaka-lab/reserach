from tests.integration.test_real_transfer import TestRealTransferIntegration
t = TestRealTransferIntegration("test_full_upload_download_success")
t.setUpClass()
t.setUp()
t.test_full_upload_download_success()
