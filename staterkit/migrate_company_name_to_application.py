import sqlite3
from pathlib import Path

# Determine the database path
db_file = 'cuba.db'
base_dir = Path(__file__).parent
db_path = base_dir / 'instance' / db_file

if not db_path.exists():
    print(f"Database not found at {db_path}. Please ensure the database exists.")
    exit(1)

print(f"Migrating database at {db_path}...")
conn = sqlite3.connect(str(db_path))
cursor = conn.cursor()

try:
    # Check if breached_credential table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='breached_credential'")
    if not cursor.fetchone():
        print("'breached_credential' table does not exist. Skipping migration.")
        exit(0)
    
    # Check current columns
    cursor.execute("PRAGMA table_info(breached_credential)")
    columns = [col[1] for col in cursor.fetchall()]
    
    # Check if company_name column exists and application doesn't
    if 'company_name' in columns and 'application' not in columns:
        print("Renaming 'company_name' column to 'application' in breached_credential table...")
        
        # SQLite 3.25.0+ supports ALTER TABLE RENAME COLUMN
        # For older versions, we'll use a workaround
        try:
            # Try the modern syntax first
            cursor.execute("ALTER TABLE breached_credential RENAME COLUMN company_name TO application")
            print("✓ Renamed 'company_name' column to 'application' using ALTER TABLE RENAME COLUMN")
        except sqlite3.OperationalError:
            # Fallback for older SQLite versions: recreate table
            print("  Using fallback method for older SQLite versions...")
            
            # Get all column info
            cursor.execute("PRAGMA table_info(breached_credential)")
            column_info = cursor.fetchall()
            
            # Get all data
            cursor.execute("SELECT * FROM breached_credential")
            rows = cursor.fetchall()
            column_names = [col[0] for col in cursor.description]
            company_name_index = column_names.index('company_name')
            
            # Create new table with application instead of company_name
            create_sql = """
                CREATE TABLE breached_credential_new (
                    id INTEGER NOT NULL PRIMARY KEY,
                    application VARCHAR(200) NOT NULL,
                    company_type VARCHAR(50) NOT NULL,
                    email VARCHAR(255) NOT NULL,
                    email_domain VARCHAR(200) NOT NULL,
                    username VARCHAR(200),
                    password_hash VARCHAR(255),
                    source VARCHAR(200),
                    breach_date DATE,
                    discovered_date DATE,
                    type VARCHAR(50) NOT NULL DEFAULT 'combolist',
                    leak_category VARCHAR(20) NOT NULL DEFAULT 'consumer',
                    ip_address VARCHAR(45),
                    device_info VARCHAR(200),
                    status VARCHAR(20) DEFAULT 'active',
                    is_marked BOOLEAN DEFAULT 0,
                    marked_by INTEGER,
                    marked_at DATETIME,
                    is_new BOOLEAN DEFAULT 1,
                    description TEXT,
                    company_id INTEGER,
                    created_by INTEGER NOT NULL,
                    created_at DATETIME,
                    updated_at DATETIME,
                    severity VARCHAR(20),
                    FOREIGN KEY(company_id) REFERENCES company (id),
                    FOREIGN KEY(created_by) REFERENCES user (id),
                    FOREIGN KEY(marked_by) REFERENCES user (id)
                )
            """
            cursor.execute(create_sql)
            
            # Copy data - values stay the same, just column name changes
            for row in rows:
                placeholders = ','.join(['?' for _ in range(len(row))])
                cursor.execute(f"INSERT INTO breached_credential_new VALUES ({placeholders})", tuple(row))
            
            # Drop old table and rename new one
            cursor.execute("DROP TABLE breached_credential")
            cursor.execute("ALTER TABLE breached_credential_new RENAME TO breached_credential")
            
            # Recreate indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS ix_breached_credential_application ON breached_credential(application)")
            cursor.execute("CREATE INDEX IF NOT EXISTS ix_breached_credential_email ON breached_credential(email)")
            cursor.execute("CREATE INDEX IF NOT EXISTS ix_breached_credential_email_domain ON breached_credential(email_domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS ix_breached_credential_type ON breached_credential(type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS ix_breached_credential_leak_category ON breached_credential(leak_category)")
            cursor.execute("CREATE INDEX IF NOT EXISTS ix_breached_credential_ip_address ON breached_credential(ip_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS ix_breached_credential_created_at ON breached_credential(created_at)")
            
            print("✓ Renamed 'company_name' column to 'application' using fallback method")
    elif 'application' in columns:
        print("✓ 'application' column already exists. Migration not needed.")
    else:
        print("⚠ 'company_name' column not found. Migration may not be needed.")
    
    conn.commit()
    print("\n✓ Migration completed successfully!")
    
except Exception as e:
    conn.rollback()
    print(f"\n✗ Migration failed: {e}")
    import traceback
    traceback.print_exc()
    raise
finally:
    conn.close()
