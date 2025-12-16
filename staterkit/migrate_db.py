"""
Database Migration Script
Adds new columns to existing tables for the security and company features.
"""
import sqlite3
import os
from pathlib import Path

# Get database path from Flask config
from cuba import app
with app.app_context():
    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///cuba.db')
    if db_uri.startswith('sqlite:///'):
        db_file = db_uri.replace('sqlite:///', '')
        if db_file.startswith('/'):
            db_path = Path(db_file)
        else:
            # Flask creates instance folder for SQLite databases
            instance_path = Path(__file__).parent / 'instance'
            instance_path.mkdir(exist_ok=True)
            db_path = instance_path / db_file
            # Also check in current directory
            if not db_path.exists():
                db_path = Path(__file__).parent / db_file
    else:
        print(f"Unsupported database URI: {db_uri}")
        exit(1)

if not db_path.exists():
    print(f"Database not found at {db_path}. Creating new database...")
    from cuba import app, db
    with app.app_context():
        db.create_all()
    print("✓ New database created with all tables.")
else:
    print(f"Migrating database at {db_path}...")
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    try:
        # Check and add columns to user table
        cursor.execute("PRAGMA table_info(user)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'role' not in columns:
            print("Adding 'role' column to user table...")
            cursor.execute("ALTER TABLE user ADD COLUMN role VARCHAR(20) DEFAULT 'member'")
            # Update existing users to have 'member' role
            cursor.execute("UPDATE user SET role = 'member' WHERE role IS NULL")
            # Set admin role for existing admins
            cursor.execute("UPDATE user SET role = 'admin' WHERE \"isAdmin\" = 1")
            print("✓ Added 'role' column")
        
        if 'company_id' not in columns:
            print("Adding 'company_id' column to user table...")
            cursor.execute("ALTER TABLE user ADD COLUMN company_id INTEGER")
            print("✓ Added 'company_id' column")
        
        if 'is_active' not in columns:
            print("Adding 'is_active' column to user table...")
            cursor.execute("ALTER TABLE user ADD COLUMN is_active BOOLEAN DEFAULT 1")
            cursor.execute("UPDATE user SET is_active = 1 WHERE is_active IS NULL")
            print("✓ Added 'is_active' column")
        
        if 'created_at' not in columns:
            print("Adding 'created_at' column to user table...")
            cursor.execute("ALTER TABLE user ADD COLUMN created_at DATETIME")
            print("✓ Added 'created_at' column")
        
        if 'updated_at' not in columns:
            print("Adding 'updated_at' column to user table...")
            cursor.execute("ALTER TABLE user ADD COLUMN updated_at DATETIME")
            print("✓ Added 'updated_at' column")
        
        if 'last_login' not in columns:
            print("Adding 'last_login' column to user table...")
            cursor.execute("ALTER TABLE user ADD COLUMN last_login DATETIME")
            print("✓ Added 'last_login' column")
        
        # Check and create company table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='company'")
        if not cursor.fetchone():
            print("Creating 'company' table...")
            cursor.execute("""
                CREATE TABLE company (
                    id INTEGER NOT NULL PRIMARY KEY,
                    name VARCHAR(200) NOT NULL UNIQUE,
                    domain VARCHAR(200) NOT NULL UNIQUE,
                    company_type VARCHAR(50) NOT NULL,
                    description TEXT,
                    created_at DATETIME,
                    updated_at DATETIME
                )
            """)
            # Create index if it doesn't exist
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS ix_company_domain ON company(domain)
            """)
            print("✓ Created 'company' table")
        else:
            print("✓ 'company' table already exists")
        
        # Check and add columns to breached_credential table
        cursor.execute("PRAGMA table_info(breached_credential)")
        cred_columns = [col[1] for col in cursor.fetchall()]
        
        if 'email_domain' not in cred_columns:
            print("Adding 'email_domain' column to breached_credential table...")
            cursor.execute("ALTER TABLE breached_credential ADD COLUMN email_domain VARCHAR(200)")
            # Extract domains from existing emails
            cursor.execute("UPDATE breached_credential SET email_domain = substr(email, instr(email, '@') + 1) WHERE email_domain IS NULL")
            cursor.execute("CREATE INDEX IF NOT EXISTS ix_breached_credential_email_domain ON breached_credential(email_domain)")
            print("✓ Added 'email_domain' column and populated from existing emails")
        
        if 'is_marked' not in cred_columns:
            print("Adding 'is_marked' column to breached_credential table...")
            cursor.execute("ALTER TABLE breached_credential ADD COLUMN is_marked BOOLEAN DEFAULT 0")
            print("✓ Added 'is_marked' column")
        
        if 'marked_by' not in cred_columns:
            print("Adding 'marked_by' column to breached_credential table...")
            cursor.execute("ALTER TABLE breached_credential ADD COLUMN marked_by INTEGER")
            print("✓ Added 'marked_by' column")
        
        if 'marked_at' not in cred_columns:
            print("Adding 'marked_at' column to breached_credential table...")
            cursor.execute("ALTER TABLE breached_credential ADD COLUMN marked_at DATETIME")
            print("✓ Added 'marked_at' column")
        
        if 'company_id' not in cred_columns:
            print("Adding 'company_id' column to breached_credential table...")
            cursor.execute("ALTER TABLE breached_credential ADD COLUMN company_id INTEGER")
            # Try to link existing credentials to companies based on email domain
            cursor.execute("""
                UPDATE breached_credential 
                SET company_id = (
                    SELECT company.id 
                    FROM company 
                    WHERE company.domain = breached_credential.email_domain 
                    LIMIT 1
                )
                WHERE email_domain IS NOT NULL
            """)
            print("✓ Added 'company_id' column")
        
        conn.commit()
        print("\n✓ Migration completed successfully!")
        
    except Exception as e:
        conn.rollback()
        print(f"\n✗ Migration failed: {e}")
        raise
    finally:
        conn.close()

