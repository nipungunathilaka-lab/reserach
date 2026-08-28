from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.db import Base
from app.services.blockchain_service import BlockchainService


def test_audit_chain_verification():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    BlockchainService.append_block(
        db,
        event_type="TEST_ONE",
        details={"value": 1},
    )
    BlockchainService.append_block(
        db,
        event_type="TEST_TWO",
        details={"value": 2},
    )

    valid, errors = BlockchainService.verify_chain(db)

    assert valid is True
    assert errors == []
