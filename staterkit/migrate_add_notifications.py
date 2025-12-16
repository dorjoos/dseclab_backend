#!/usr/bin/env python
"""
Migration script to add notification table
Run this script to update your database schema.
"""
import sqlite3
from pathlib import Path

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
    
    # Check if table already exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='notification'")
    if cursor.fetchone():
        print("✓ Notification table already exists. No migration needed.")
    else:
        print("Creating notification table...")
        cursor.execute("""
            CREATE TABLE notification (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                notification_type VARCHAR(50) DEFAULT 'info',
                title VARCHAR(200) NOT NULL,
                message TEXT,
                link VARCHAR(500),
                is_read BOOLEAN DEFAULT 0,
                read_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES user (id)
            )
        """)
        
        # Create index for faster queries
        cursor.execute("CREATE INDEX ix_notification_user_id ON notification(user_id)")
        cursor.execute("CREATE INDEX ix_notification_created_at ON notification(created_at)")
        cursor.execute("CREATE INDEX ix_notification_is_read ON notification(is_read)")
        
        conn.commit()
        print("✓ Successfully created notification table!")
        print("✓ Created indexes for performance")
    
    conn.close()
    print("Migration completed successfully!")
    
except sqlite3.Error as e:
    print(f"Error: {e}")
    exit(1)

