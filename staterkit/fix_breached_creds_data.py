"""
Fix breached_credential data by extracting domain from username (if username is an email)
and populating other missing fields where possible.
"""
import sqlite3
from pathlib import Path

# Determine the database path
db_file = 'cuba.db'
base_dir = Path(__file__).parent
db_path = base_dir / 'instance' / db_file

if not db_path.exists():
    print(f"Database not found at {db_path}")
    exit(1)

print(f"Fixing data in database at {db_path}...")
conn = sqlite3.connect(str(db_path))
cursor = conn.cursor()

try:
    # Get all records with username but no domain
    cursor.execute("SELECT id, username FROM breached_credential WHERE username IS NOT NULL AND username != '' AND (domain IS NULL OR domain = '')")
    records = cursor.fetchall()
    
    updated_count = 0
    for record_id, username in records:
        # Extract domain from username if it's an email
        if '@' in username:
            domain = username.split('@')[1].lower().strip()
            cursor.execute("UPDATE breached_credential SET domain = ? WHERE id = ?", (domain, record_id))
            updated_count += 1
            print(f"  Updated record {record_id}: extracted domain '{domain}' from username '{username}'")
    
    # Also set domain to username if username doesn't contain @ but looks like a domain
    cursor.execute("SELECT id, username FROM breached_credential WHERE username IS NOT NULL AND username != '' AND username NOT LIKE '%@%' AND (domain IS NULL OR domain = '')")
    records = cursor.fetchall()
    
    for record_id, username in records:
        # If username looks like a domain (contains dot), use it as domain
        if '.' in username:
            cursor.execute("UPDATE breached_credential SET domain = ? WHERE id = ?", (username.lower().strip(), record_id))
            updated_count += 1
            print(f"  Updated record {record_id}: set domain to '{username}'")
    
    conn.commit()
    print(f"\n✓ Updated {updated_count} records with domain information")
    
    # Show summary
    cursor.execute("SELECT COUNT(*) as total, COUNT(domain) as has_domain, COUNT(username) as has_username, COUNT(source) as has_source FROM breached_credential")
    stats = cursor.fetchone()
    print(f"\nSummary:")
    print(f"  Total records: {stats[0]}")
    print(f"  Records with domain: {stats[1]}")
    print(f"  Records with username: {stats[2]}")
    print(f"  Records with source: {stats[3]}")
    
except Exception as e:
    conn.rollback()
    print(f"\n✗ Error: {e}")
    import traceback
    traceback.print_exc()
    raise
finally:
    conn.close()

