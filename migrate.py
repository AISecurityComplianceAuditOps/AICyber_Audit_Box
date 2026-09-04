import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.db.database import Base, MCPServerConfig, AssetInventoryVersion, SessionLocal

def recreate_tables():
    db = SessionLocal()
    engine = db.get_bind()
    print("Dropping MCPServerConfig table...")
    MCPServerConfig.__table__.drop(engine, checkfirst=True)
    AssetInventoryVersion.__table__.drop(engine, checkfirst=True)
    print("Creating new tables...")
    Base.metadata.create_all(engine)
    print("Migration complete.")
    db.close()

if __name__ == "__main__":
    recreate_tables()
