"""
Database Migration Script
Creates watchlist_entry table for multiple watchlist entries per company.
This script can be run independently without Flask imports.
"""
import sqlite3
from pathlib import Path

# Try to find the database file
db_paths = [
    Path(__file__).parent / 'instance' / 'cuba.db',
    Path(__file__).parent / 'cuba.db',
]

db_path = None
for path in db_paths:
    if path.exists():
        db_path = path
        break

if not db_path:
    print("Database not found. Tried:")
    for path in db_paths:
        print(f"  - {path}")
    print("\nPlease ensure the database exists or specify the path manually.")
    exit(1)

print(f"Migrating database at {db_path}...")
conn = sqlite3.connect(str(db_path))
cursor = conn.cursor()

try:
    # Check if watchlist_entry table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='watchlist_entry'")
    if cursor.fetchone():
        print("✓ 'watchlist_entry' table already exists")
    else:
        print("Creating 'watchlist_entry' table...")
        cursor.execute("""
            CREATE TABLE watchlist_entry (
                id INTEGER NOT NULL PRIMARY KEY,
                company_id INTEGER NOT NULL,
                entry_type VARCHAR(20) NOT NULL,
                entry_value VARCHAR(500) NOT NULL,
                description TEXT,
                created_at DATETIME,
                updated_at DATETIME,
                FOREIGN KEY(company_id) REFERENCES company (id)
            )
        """)
        # Create index for faster lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS ix_watchlist_entry_company_id ON watchlist_entry(company_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS ix_watchlist_entry_type ON watchlist_entry(entry_type)
        """)
        print("✓ Created 'watchlist_entry' table with indexes")
    
    # Optional: Migrate old watchlist fields to new table (if they exist)
    cursor.execute("PRAGMA table_info(company)")
    company_columns = [col[1] for col in cursor.fetchall()]
    
    old_fields = ['watchlist_domain', 'watchlist_url', 'watchlist_email', 'watchlist_slug']
    has_old_fields = any(field in company_columns for field in old_fields)
    
    if has_old_fields:
        print("\nMigrating old watchlist fields to new watchlist_entry table...")
        cursor.execute("SELECT id, watchlist_domain, watchlist_url, watchlist_email, watchlist_slug FROM company")
        companies = cursor.fetchall()
        
        migrated_count = 0
        for company_id, domain, url, email, slug in companies:
            if domain:
                cursor.execute("""
                    INSERT INTO watchlist_entry (company_id, entry_type, entry_value, created_at, updated_at)
                    SELECT ?, 'domain', ?, datetime('now'), datetime('now')
                    WHERE NOT EXISTS (
                        SELECT 1 FROM watchlist_entry 
                        WHERE company_id = ? AND entry_type = 'domain' AND entry_value = ?
                    )
                """, (company_id, domain, company_id, domain))
                migrated_count += 1
            if url:
                cursor.execute("""
                    INSERT INTO watchlist_entry (company_id, entry_type, entry_value, created_at, updated_at)
                    SELECT ?, 'url', ?, datetime('now'), datetime('now')
                    WHERE NOT EXISTS (
                        SELECT 1 FROM watchlist_entry 
                        WHERE company_id = ? AND entry_type = 'url' AND entry_value = ?
                    )
                """, (company_id, url, company_id, url))
                migrated_count += 1
            if email:
                cursor.execute("""
                    INSERT INTO watchlist_entry (company_id, entry_type, entry_value, created_at, updated_at)
                    SELECT ?, 'email', ?, datetime('now'), datetime('now')
                    WHERE NOT EXISTS (
                        SELECT 1 FROM watchlist_entry 
                        WHERE company_id = ? AND entry_type = 'email' AND entry_value = ?
                    )
                """, (company_id, email, company_id, email))
                migrated_count += 1
            if slug:
                cursor.execute("""
                    INSERT INTO watchlist_entry (company_id, entry_type, entry_value, created_at, updated_at)
                    SELECT ?, 'slug', ?, datetime('now'), datetime('now')
                    WHERE NOT EXISTS (
                        SELECT 1 FROM watchlist_entry 
                        WHERE company_id = ? AND entry_type = 'slug' AND entry_value = ?
                    )
                """, (company_id, slug, company_id, slug))
                migrated_count += 1
        
        if migrated_count > 0:
            print(f"✓ Migrated {migrated_count} watchlist entries from old fields")
        else:
            print("✓ No old watchlist data to migrate")
    
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

