#!/usr/bin/env python
"""
Migration script to add is_new column to breached_credential table
Run this script to update your database schema.
"""
import sqlite3
import os
from pathlib import Path

# Get database path
db_path = Path(__file__).parent / 'cuba.db'
if not db_path.exists():
    # Try instance directory
    db_path = Path(__file__).parent / 'instance' / 'cuba.db'
    if not db_path.exists():
        print(f"Error: Database not found at {db_path}")
        print("Please check your database location.")
        exit(1)

print(f"Connecting to database: {db_path}")

try:
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # Check if column already exists
    cursor.execute("PRAGMA table_info(breached_credential)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if 'is_new' in columns:
        print("✓ Column 'is_new' already exists. No migration needed.")
    else:
        print("Adding 'is_new' column to breached_credential table...")
        # Add the column with default value True (1 in SQLite)
        cursor.execute("""
            ALTER TABLE breached_credential 
            ADD COLUMN is_new BOOLEAN DEFAULT 1
        """)
        
        # Set all existing records to is_new = False (0) since they're not new
        cursor.execute("""
            UPDATE breached_credential 
            SET is_new = 0
        """)
        
        conn.commit()
        print("✓ Successfully added 'is_new' column!")
        print("✓ Set all existing records to is_new = False")
    
    conn.close()
    print("Migration completed successfully!")
    
except sqlite3.Error as e:
    print(f"Error: {e}")
    exit(1)

