"""
Migration script to update breached_credential table with new field structure.

New fields: _id, _ignored, _index, _score, domain, password, source, type, url, username
Old fields (removed): application, company_type, email, email_domain, password_hash, 
                     breach_date, discovered_date, leak_category, ip_address, device_info, 
                     status, is_new, description, severity

Note: This migration will create a new table structure. Existing data will be lost.
If you need to preserve data, modify this script to map old fields to new ones.
"""
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
print("⚠ WARNING: This migration will recreate the breached_credential table with new fields.")
print("⚠ Existing data will be lost unless you modify this script to preserve it.")
print()

conn = sqlite3.connect(str(db_path))
cursor = conn.cursor()

try:
    # Check if breached_credential table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='breached_credential'")
    if not cursor.fetchone():
        print("'breached_credential' table does not exist. Creating new table...")
        # Create new table with new structure
        create_sql = """
            CREATE TABLE breached_credential (
                id INTEGER NOT NULL PRIMARY KEY,
                _id VARCHAR(200),
                _ignored BOOLEAN DEFAULT 0,
                _index VARCHAR(200),
                _score REAL,
                domain VARCHAR(200),
                password VARCHAR(500),
                source VARCHAR(200),
                type VARCHAR(50),
                url VARCHAR(500),
                username VARCHAR(200),
                is_marked BOOLEAN DEFAULT 0,
                marked_by INTEGER,
                marked_at DATETIME,
                company_id INTEGER,
                created_by INTEGER NOT NULL,
                created_at DATETIME,
                updated_at DATETIME,
                FOREIGN KEY(company_id) REFERENCES company (id),
                FOREIGN KEY(created_by) REFERENCES user (id),
                FOREIGN KEY(marked_by) REFERENCES user (id)
            )
        """
        cursor.execute(create_sql)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_breached_credential__id ON breached_credential(_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_breached_credential_domain ON breached_credential(domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_breached_credential_type ON breached_credential(type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_breached_credential_username ON breached_credential(username)")
        
        print("✓ Created new breached_credential table with new structure")
    else:
        print("'breached_credential' table exists. Recreating with new structure...")
        
        # Get current column info
        cursor.execute("PRAGMA table_info(breached_credential)")
        old_columns = [col[1] for col in cursor.fetchall()]
        
        # Check if already migrated
        if '_id' in old_columns and 'domain' in old_columns and 'username' in old_columns:
            print("✓ Table already has new structure. Migration not needed.")
            conn.commit()
            conn.close()
            exit(0)
        
        # Backup old table name
        cursor.execute("ALTER TABLE breached_credential RENAME TO breached_credential_old")
        print("✓ Renamed old table to breached_credential_old")
        
        # Create new table with new structure
        create_sql = """
            CREATE TABLE breached_credential (
                id INTEGER NOT NULL PRIMARY KEY,
                _id VARCHAR(200),
                _ignored BOOLEAN DEFAULT 0,
                _index VARCHAR(200),
                _score REAL,
                domain VARCHAR(200),
                password VARCHAR(500),
                source VARCHAR(200),
                type VARCHAR(50),
                url VARCHAR(500),
                username VARCHAR(200),
                is_marked BOOLEAN DEFAULT 0,
                marked_by INTEGER,
                marked_at DATETIME,
                company_id INTEGER,
                created_by INTEGER NOT NULL,
                created_at DATETIME,
                updated_at DATETIME,
                FOREIGN KEY(company_id) REFERENCES company (id),
                FOREIGN KEY(created_by) REFERENCES user (id),
                FOREIGN KEY(marked_by) REFERENCES user (id)
            )
        """
        cursor.execute(create_sql)
        print("✓ Created new breached_credential table with new structure")
        
        # Optional: Migrate data if you want to preserve some fields
        # This is a basic example - you may want to customize this based on your needs
        try:
            cursor.execute("SELECT id, username, source, type, is_marked, marked_by, marked_at, company_id, created_by, created_at, updated_at FROM breached_credential_old")
            old_rows = cursor.fetchall()
            
            if old_rows:
                print(f"  Found {len(old_rows)} existing records.")
                print("  Note: Only compatible fields will be migrated (id, username, source, type, is_marked, etc.)")
                print("  Other fields (application, email, etc.) will be lost.")
                
                migrate_count = 0
                for row in old_rows:
                    try:
                        cursor.execute("""
                            INSERT INTO breached_credential 
                            (id, username, source, type, is_marked, marked_by, marked_at, company_id, created_by, created_at, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, row)
                        migrate_count += 1
                    except Exception as e:
                        print(f"  Warning: Could not migrate row {row[0]}: {e}")
                        continue
                
                print(f"  ✓ Migrated {migrate_count} records")
        except Exception as e:
            print(f"  ⚠ Could not migrate existing data: {e}")
            print("  Continuing with empty table...")
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_breached_credential__id ON breached_credential(_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_breached_credential_domain ON breached_credential(domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_breached_credential_type ON breached_credential(type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_breached_credential_username ON breached_credential(username)")
        print("✓ Created indexes")
        
        # Drop old table (optional - comment out if you want to keep backup)
        print("\n⚠ Dropping old table 'breached_credential_old'...")
        cursor.execute("DROP TABLE breached_credential_old")
        print("✓ Dropped old table")
    
    conn.commit()
    print("\n✓ Migration completed successfully!")
    print("\nNote: If you need to restore data from the old table, check if 'breached_credential_old' still exists.")
    
except Exception as e:
    conn.rollback()
    print(f"\n✗ Migration failed: {e}")
    import traceback
    traceback.print_exc()
    raise
finally:
    conn.close()

