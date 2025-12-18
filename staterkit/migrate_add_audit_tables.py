import sqlite3
from pathlib import Path
from datetime import datetime

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
    # Create audit_log table
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'")
    if not cursor.fetchone():
        print("Creating 'audit_log' table...")
        cursor.execute("""
            CREATE TABLE audit_log (
                id INTEGER NOT NULL PRIMARY KEY,
                user_id INTEGER,
                action_type VARCHAR(50) NOT NULL,
                resource_type VARCHAR(50) NOT NULL,
                resource_id INTEGER,
                description TEXT NOT NULL,
                ip_address VARCHAR(45),
                user_agent VARCHAR(500),
                old_values TEXT,
                new_values TEXT,
                status VARCHAR(20) NOT NULL DEFAULT 'success',
                error_message TEXT,
                created_at DATETIME,
                FOREIGN KEY(user_id) REFERENCES user (id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_audit_log_action_type ON audit_log(action_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_audit_log_resource_type ON audit_log(resource_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_audit_log_created_at ON audit_log(created_at)")
        print("✓ Created 'audit_log' table with indexes")
    else:
        print("✓ 'audit_log' table already exists")
    
    # Create user_activity table
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user_activity'")
    if not cursor.fetchone():
        print("Creating 'user_activity' table...")
        cursor.execute("""
            CREATE TABLE user_activity (
                id INTEGER NOT NULL PRIMARY KEY,
                user_id INTEGER,
                activity_type VARCHAR(50) NOT NULL,
                ip_address VARCHAR(45),
                user_agent VARCHAR(500),
                location VARCHAR(200),
                status VARCHAR(20) NOT NULL DEFAULT 'success',
                failure_reason VARCHAR(200),
                created_at DATETIME,
                FOREIGN KEY(user_id) REFERENCES user (id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_user_activity_activity_type ON user_activity(activity_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_user_activity_ip_address ON user_activity(ip_address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_user_activity_created_at ON user_activity(created_at)")
        print("✓ Created 'user_activity' table with indexes")
    else:
        print("✓ 'user_activity' table already exists")
    
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

