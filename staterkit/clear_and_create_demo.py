#!/usr/bin/env python
"""
Script to clear old breached data and create new demo data with new field structure
"""
import sqlite3
import random
from pathlib import Path
from datetime import datetime, timedelta

# Determine the database path
db_file = 'cuba.db'
base_dir = Path(__file__).parent
db_path = base_dir / 'instance' / db_file

if not db_path.exists():
    print(f"Database not found at {db_path}")
    exit(1)

# Company domains
COMPANIES = [
    {'domain': 'techcorp.com', 'id': 1},
    {'domain': 'globaltel.com', 'id': 2},
    {'domain': 'nsa.gov', 'id': 3},
    {'domain': 'megaretail.com', 'id': 4},
]

# Data for generation
FIRST_NAMES = ['john', 'jane', 'mike', 'sarah', 'david', 'emily', 'chris', 'lisa', 'robert', 'amanda',
               'james', 'jennifer', 'william', 'michelle', 'richard', 'karen', 'joseph', 'nancy',
               'thomas', 'betty', 'charles', 'helen', 'daniel', 'sandra', 'matthew', 'donna']

SOURCES = [
    'Dark Web Marketplace',
    'Pastebin',
    'Telegram Channel',
    'Data Breach Forum',
    'Stealer Log',
    'Malware Analysis',
    'Threat Intelligence Feed',
    'Security Researcher'
]

LEAK_TYPES = ['combolist', 'stealer', 'malware', 'pastebin', 'breach', 'phishing', 'darkweb']

print(f"Clearing and creating demo data in database at {db_path}...")
conn = sqlite3.connect(str(db_path))
cursor = conn.cursor()

try:
    # Clear existing breached credentials
    cursor.execute("DELETE FROM breached_credential")
    deleted_count = cursor.rowcount
    print(f"✓ Deleted {deleted_count} existing breached credentials")
    
    # Get admin user ID (created_by)
    cursor.execute("SELECT id FROM user WHERE role = 'admin' OR isAdmin = 1 LIMIT 1")
    admin_result = cursor.fetchone()
    if not admin_result:
        print("⚠ Warning: No admin user found. Using user ID 1 as fallback.")
        admin_user_id = 1
    else:
        admin_user_id = admin_result[0]
    
    # Create new demo data
    total_created = 0
    for company in COMPANIES:
        print(f"\nCreating credentials for {company['domain']}...")
        
        for i in range(20):
            # Generate username
            first_name = random.choice(FIRST_NAMES)
            if random.random() > 0.5:  # 50% email format
                username = f"{first_name}{random.randint(1, 999)}@{company['domain']}"
            else:
                username = f"{first_name}{random.randint(1, 999)}"
            
            # Generate domain
            domain = company['domain']
            if random.random() > 0.8:  # 20% different domain
                domain = random.choice(['example.com', 'test.com', 'demo.org'])
            
            # Generate password (30% chance)
            password = None
            if random.random() > 0.7:
                password = f"Pass{random.randint(1000, 9999)}!"
            
            # Generate source and type
            source = random.choice(SOURCES)
            leak_type = random.choice(LEAK_TYPES)
            
            # Generate URL (40% chance)
            url = None
            if random.random() > 0.6:
                url = f"https://{random.choice(['pastebin.com', 'github.com', 'example.com'])}/leak/{random.randint(1000, 9999)}"
            
            # Generate Elasticsearch-like fields
            _id = f"breach_{company['domain']}_{i}_{random.randint(10000, 99999)}"
            _index = random.choice(['breaches-2024', 'leaks-2024', 'credentials-2024'])
            _score = round(random.uniform(0.5, 10.0), 2) if random.random() > 0.3 else None
            _ignored = 1 if random.random() > 0.9 else 0  # 10% ignored
            
            # Generate created_at (within last 90 days)
            days_ago = random.randint(0, 90)
            created_at = datetime.now() - timedelta(days=days_ago)
            
            # Insert record
            cursor.execute("""
                INSERT INTO breached_credential 
                (_id, _ignored, _index, _score, domain, password, source, type, url, username,
                 is_marked, company_id, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                _id,
                _ignored,
                _index,
                _score,
                domain,
                password,
                source,
                leak_type,
                url,
                username,
                1 if random.random() > 0.7 else 0,  # 30% marked
                company['id'],
                admin_user_id,
                created_at,
                created_at
            ))
            total_created += 1
    
    conn.commit()
    print(f"\n✓ Created {total_created} new breached credentials")
    
    # Show summary
    cursor.execute("SELECT COUNT(*) as total, COUNT(domain) as has_domain, COUNT(username) as has_username, COUNT(password) as has_password, COUNT(source) as has_source FROM breached_credential")
    stats = cursor.fetchone()
    print(f"\nSummary:")
    print(f"  Total records: {stats[0]}")
    print(f"  Records with domain: {stats[1]}")
    print(f"  Records with username: {stats[2]}")
    print(f"  Records with password: {stats[3]}")
    print(f"  Records with source: {stats[4]}")
    print("\n✓ Demo data creation completed!")
    
except Exception as e:
    conn.rollback()
    print(f"\n✗ Error: {e}")
    import traceback
    traceback.print_exc()
    raise
finally:
    conn.close()

