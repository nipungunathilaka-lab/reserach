import re

class DataClassificationScanner:
    SENSITIVE_KEYWORDS = ["confidential", "password", "medical"]
    
    # Simple regex patterns for credit cards and SSNs (for demonstration/scanning purposes)
    # Visa, MasterCard, Amex, Discover typical lengths/prefixes, simplified for speed
    CC_REGEX = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
    SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    
    @classmethod
    def scan(cls, file_bytes: bytes, file_name: str) -> str:
        # 1. Scan metadata (filename)
        name_lower = file_name.lower()
        for kw in cls.SENSITIVE_KEYWORDS:
            if kw in name_lower:
                return "Sensitive"

        # 2. Scan file content (first 10KB to avoid memory/perf issues on large files)
        scan_size = min(len(file_bytes), 10 * 1024)
        content_to_scan = file_bytes[:scan_size]
        
        # Try to decode as UTF-8, ignore errors (works for text and some binaries)
        try:
            text_content = content_to_scan.decode('utf-8', errors='ignore').lower()
        except Exception:
            text_content = ""

        if text_content:
            # Check keywords
            for kw in cls.SENSITIVE_KEYWORDS:
                if kw in text_content:
                    return "Sensitive"
                    
            # Check Regex (Credit Card / SSN)
            if cls.CC_REGEX.search(text_content):
                return "Sensitive"
                
            if cls.SSN_REGEX.search(text_content):
                return "Sensitive"

        return "Normal"
