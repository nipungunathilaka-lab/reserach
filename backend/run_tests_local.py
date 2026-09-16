import pytest
import sys

if __name__ == "__main__":
    # Disable pytest plugins that might crash (like pytest_ethereum)
    sys.exit(pytest.main(["-p", "no:web3", "-p", "no:ethereum", "tests/test_dp_integration.py"]))
