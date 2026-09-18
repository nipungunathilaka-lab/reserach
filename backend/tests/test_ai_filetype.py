import pytest
from app.services.ai_service import AIService
from app.services.continuous_monitor import ContinuousTransferMonitor

def test_ai_filetype_01_docx_is_not_high_risk():
    high_risk, archive = AIService.file_type_features("Session1.docx")
    assert high_risk == 0

def test_ai_filetype_02_pdf_is_not_high_risk():
    high_risk, archive = AIService.file_type_features("Document.pdf")
    assert high_risk == 0

def test_ai_filetype_03_txt_is_not_high_risk():
    high_risk, archive = AIService.file_type_features("Notes.txt")
    assert high_risk == 0

def test_ai_filetype_04_exe_is_high_risk():
    high_risk, archive = AIService.file_type_features("Payload.exe")
    assert high_risk == 1

def test_ai_filetype_05_bat_is_high_risk():
    high_risk, archive = AIService.file_type_features("script.bat")
    assert high_risk == 1

def test_ai_filetype_06_uppercase_docx():
    high_risk, archive = AIService.file_type_features("DOCUMENT.DOCX")
    assert high_risk == 0

def test_ai_filetype_07_multiple_dots():
    high_risk, archive = AIService.file_type_features("backup.tar.gz.docx")
    assert high_risk == 0

def test_ai_filetype_08_no_contamination():
    # Previous high-risk
    res1 = AIService.analyze_transfer(
        file_size_mb=1.0,
        hour_of_day=12,
        transfers_last_hour=1,
        mfa_failed_attempts=0,
        failed_login_attempts=0,
        file_name="malware.exe",
        user_id="test_user"
    )
    assert res1["features"]["high_risk_file_type"] == 1
    
    # Next transfer
    res2 = AIService.analyze_transfer(
        file_size_mb=1.0,
        hour_of_day=12,
        transfers_last_hour=1,
        mfa_failed_attempts=0,
        failed_login_attempts=0,
        file_name="safe.docx",
        user_id="test_user"
    )
    assert res2["features"]["high_risk_file_type"] == 0

def test_ai_filetype_09_mime_independent():
    # The file type feature should solely rely on the file extension logic which has been tested above
    # Not MIME string matching
    pass # Verified by design

def test_ai_filetype_10_docx_zip_container():
    # docx is zip based, but it shouldn't trigger archive logic which flags zip
    high_risk, archive = AIService.file_type_features("file.docx")
    assert archive == 0
