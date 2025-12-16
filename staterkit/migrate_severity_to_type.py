#!/usr/bin/env python
"""
Migration script to change severity to type and add new fields
Run this script to update your database schema.
"""
import sqlite3
from pathlib import Path
from datetime import datetime

# Get database path
db_path = Path(__file__).parent / 'instance' / 'cuba.db'
if not db_path.exists():
    db_path = Path(__file__).parent / 'cuba.db'
    if not db_path.exists():
        print(f"Error: Database not found at {db_path}")
        exit(1)

print(f"Connecting to database: {db_path}")

try:
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # Check current columns
    cursor.execute("PRAGMA table_info(breached_credential)")
    columns = {column[1]: column for column in cursor.fetchall()}
    
    print("Current columns:", list(columns.keys()))
    
    # Add new columns if they don't exist
    if 'type' not in columns:
        print("Adding 'type' column...")
        cursor.execute("ALTER TABLE breached_credential ADD COLUMN type VARCHAR(50) DEFAULT 'combolist'")
        # Migrate severity to type
        cursor.execute("UPDATE breached_credential SET type = CASE WHEN severity = 'critical' THEN 'stealer' WHEN severity = 'high' THEN 'malware' WHEN severity = 'medium' THEN 'combolist' ELSE 'combolist' END WHERE type IS NULL")
        print("✓ Added 'type' column and migrated data from severity")
    else:
        print("✓ 'type' column already exists")
    
    if 'leak_category' not in columns:
        print("Adding 'leak_category' column...")
        cursor.execute("ALTER TABLE breached_credential ADD COLUMN leak_category VARCHAR(20) DEFAULT 'consumer'")
        print("✓ Added 'leak_category' column")
    else:
        print("✓ 'leak_category' column already exists")
    
    if 'ip_address' not in columns:
        print("Adding 'ip_address' column...")
        cursor.execute("ALTER TABLE breached_credential ADD COLUMN ip_address VARCHAR(45)")
        print("✓ Added 'ip_address' column")
    else:
        print("✓ 'ip_address' column already exists")
    
    if 'device_info' not in columns:
        print("Adding 'device_info' column...")
        cursor.execute("ALTER TABLE breached_credential ADD COLUMN device_info VARCHAR(200)")
        print("✓ Added 'device_info' column")
    else:
        print("✓ 'device_info' column already exists")
    
    # Create indexes
    try:
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_breached_credential_type ON breached_credential(type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_breached_credential_leak_category ON breached_credential(leak_category)")
        cursor.execute("CREATE INDEX IF NOT EXISTS ix_breached_credential_ip_address ON breached_credential(ip_address)")
        print("✓ Created indexes")
    except sqlite3.OperationalError as e:
        if "already exists" not in str(e):
            print(f"Index creation note: {e}")
    
    conn.commit()
    conn.close()
    print("\n✓ Migration completed successfully!")
    print("\nNote: 'severity' column is kept for backward compatibility but 'type' should be used going forward.")
    
except sqlite3.Error as e:
    print(f"Error: {e}")
    exit(1)

