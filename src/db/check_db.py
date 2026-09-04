import sqlalchemy
from sqlalchemy import create_engine

# ShakthiDB Connection URL (Workshop Port: 15234)
DB_URL = "postgresql://postgres:ShakthiDB%402026@localhost:15234/shakthidb"

def test_connection():
    print(f"Attempting to connect to ShakthiDB at: {DB_URL}")
    try:
        engine = create_engine(DB_URL)
        connection = engine.connect()
        print("[SUCCESS] ShakthiDB is connected and working!")
        connection.close()
    except Exception as e:
        print("[FAILED] Could not connect to ShakthiDB.")
        print(f"\nError Details: {e}")
        print("\nPossible solutions:")
        print("1. Ensure PostgreSQL is installed and running on your machine.")
        print("2. Check if the username 'shakthi' and password 'StrongPassword123' are correct.")
        print("3. Ensure the database 'shakthidb' has been created.")
        print("4. If using Docker, make sure your container is running.")

if __name__ == "__main__":
    test_connection()
