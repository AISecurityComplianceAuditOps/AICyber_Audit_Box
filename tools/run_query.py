import sys
from sqlalchemy import create_engine, text

def run_query(query_str, db_name="shakthidb_master"):
    # Connect directly to specified PostgreSQL database
    try:
        url = f"postgresql://postgres:ShakthiDB%402026@localhost:15234/{db_name}"
        engine = create_engine(url, connect_args={"connect_timeout": 2})
        with engine.connect() as conn:
            print(f"Connected to PostgreSQL ({db_name})")
            result = conn.execute(text(query_str))
            
            # If it's a SELECT query, print the results
            if result.returns_rows:
                rows = result.fetchall()
                if not rows:
                    print("Query returned 0 rows.")
                for row in rows:
                    print(row)
            else:
                conn.commit()
                print("Query executed successfully.")
    except Exception as e:
        print(f"Error executing query on {db_name}: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Check target database flag
        db_target = "shakthidb_master"
        query_start_idx = 1
        
        first_arg = sys.argv[1]
        if first_arg == "--slave1":
            db_target = "shakthidb_slave1"
            query_start_idx = 2
        elif first_arg == "--slave2":
            db_target = "shakthidb_slave2"
            query_start_idx = 2
        elif first_arg == "--master":
            db_target = "shakthidb_master"
            query_start_idx = 2
            
        query = " ".join(sys.argv[query_start_idx:])
        if query.strip():
            run_query(query, db_target)
        else:
            print("Usage: python run_query.py [--master|--slave1|--slave2] \"YOUR SQL QUERY\"")
    else:
        print("Usage: python run_query.py [--master|--slave1|--slave2] \"YOUR SQL QUERY\"")
        print("Example: python run_query.py \"SELECT * FROM users\"")
        print("Example (Query Slave 1): python run_query.py --slave1 \"SELECT * FROM users\"")
