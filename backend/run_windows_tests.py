import pytest
import json
import os

class JSONReport:
    def __init__(self):
        self.summary = {}
        
    def pytest_terminal_summary(self, terminalreporter, exitstatus, config):
        self.summary = {
            "collected": getattr(terminalreporter, "_numcollected", 0),
            "passed": len(terminalreporter.stats.get("passed", [])),
            "failed": len(terminalreporter.stats.get("failed", [])),
            "skipped": len(terminalreporter.stats.get("skipped", [])),
            "deselected": len(terminalreporter.stats.get("deselected", [])),
            "errors": len(terminalreporter.stats.get("error", [])),
            "exitcode": exitstatus
        }
        os.makedirs("tests/results", exist_ok=True)
        with open("tests/results/windows_unit_test_summary.json", "w") as f:
            json.dump(self.summary, f, indent=4)

if __name__ == "__main__":
    plugin = JSONReport()
    pytest.main(["-m", "unit and not docker", "-v"], plugins=[plugin])
