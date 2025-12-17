"""
Database Migration Script
Adds watchlist columns to the company table.
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
    # Check if company table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='company'")
    if not cursor.fetchone():
        print("✗ Company table does not exist. Please run migrate_db.py first.")
        exit(1)
    
    # Check and add watchlist columns to company table
    cursor.execute("PRAGMA table_info(company)")
    columns = [col[1] for col in cursor.fetchall()]
    
    if 'watchlist_domain' not in columns:
        print("Adding 'watchlist_domain' column to company table...")
        cursor.execute("ALTER TABLE company ADD COLUMN watchlist_domain VARCHAR(200)")
        print("✓ Added 'watchlist_domain' column")
    else:
        print("✓ 'watchlist_domain' column already exists")
    
    if 'watchlist_url' not in columns:
        print("Adding 'watchlist_url' column to company table...")
        cursor.execute("ALTER TABLE company ADD COLUMN watchlist_url VARCHAR(500)")
        print("✓ Added 'watchlist_url' column")
    else:
        print("✓ 'watchlist_url' column already exists")
    
    if 'watchlist_email' not in columns:
        print("Adding 'watchlist_email' column to company table...")
        cursor.execute("ALTER TABLE company ADD COLUMN watchlist_email VARCHAR(255)")
        print("✓ Added 'watchlist_email' column")
    else:
        print("✓ 'watchlist_email' column already exists")
    
    if 'watchlist_slug' not in columns:
        print("Adding 'watchlist_slug' column to company table...")
        cursor.execute("ALTER TABLE company ADD COLUMN watchlist_slug VARCHAR(200)")
        print("✓ Added 'watchlist_slug' column")
    else:
        print("✓ 'watchlist_slug' column already exists")
    
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
