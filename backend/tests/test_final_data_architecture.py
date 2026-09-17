import pytest
pytestmark = [pytest.mark.unit]
import pytest
from app.database.models import AuditBlock, PQCKey, ECDHPrekey, QuarantineItem

def test_no_legacy_tables_exist():
    """Verify that User, Transfer, AIAlert, BlockchainLog, etc. are not in the SQLite schema."""
    try:
        from app.database.models import User
        assert False, "User model should not exist in FastAPI backend."
    except ImportError:
        pass

    try:
        from app.database.models import Transfer
        assert False, "Transfer model should not exist in FastAPI backend."
    except ImportError:
        pass

def test_models_have_correct_foreign_keys():
    """Verify that PQCKey and ECDHPrekey use str for user_id and have no foreign key constraint to users."""
    assert PQCKey.user_id.type.python_type is str
    assert len(PQCKey.user_id.foreign_keys) == 0

    assert ECDHPrekey.user_id.type.python_type is str
    assert len(ECDHPrekey.user_id.foreign_keys) == 0

def test_psycopg2_removed():
    """Verify that psycopg2 is not in requirements.txt."""
    with open("requirements.txt", "r") as f:
        content = f.read()
        assert "psycopg2" not in content, "psycopg2 should be removed from requirements.txt"
