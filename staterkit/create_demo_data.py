#!/usr/bin/env python
"""
Script to create demo data for the Threat Intelligence Platform
Creates 4 companies with 20 breached credentials each (80 total)
"""
import random
from datetime import date, timedelta, datetime
from cuba import app, db
from cuba.models import Company, BreachedCredential, User

# Company data
COMPANIES = [
    {
        'name': 'TechCorp Bank',
        'domain': 'techcorp.com',
        'company_type': 'bank'
    },
    {
        'name': 'Global Telecom',
        'domain': 'globaltel.com',
        'company_type': 'operator'
    },
    {
        'name': 'National Security Agency',
        'domain': 'nsa.gov',
        'company_type': 'government'
    },
    {
        'name': 'Mega Retail Inc',
        'domain': 'megaretail.com',
        'company_type': 'other'
    }
]

# Leak types
LEAK_TYPES = ['combolist', 'stealer', 'malware', 'pastebin', 'breach', 'phishing', 'darkweb']

# Leak categories
LEAK_CATEGORIES = ['consumer', 'corporate']

# Status options
STATUS_OPTIONS = ['active', 'new']

# Sample names for generating emails
FIRST_NAMES = ['john', 'jane', 'mike', 'sarah', 'david', 'emily', 'chris', 'lisa', 'robert', 'amanda',
               'james', 'jennifer', 'william', 'michelle', 'richard', 'karen', 'joseph', 'nancy',
               'thomas', 'betty', 'charles', 'helen', 'daniel', 'sandra', 'matthew', 'donna']

LAST_NAMES = ['smith', 'johnson', 'williams', 'brown', 'jones', 'garcia', 'miller', 'davis', 'rodriguez',
              'martinez', 'hernandez', 'lopez', 'wilson', 'anderson', 'thomas', 'taylor', 'moore',
              'jackson', 'martin', 'lee', 'thompson', 'white', 'harris', 'sanchez', 'clark']

# IP address ranges for generating IPs
IP_RANGES = [
    '192.168.1.',
    '10.0.0.',
    '172.16.0.',
    '203.0.113.',
    '198.51.100.'
]

# Device info samples
DEVICE_INFOS = [
    'Windows 10 Pro',
    'Windows 11 Enterprise',
    'macOS 13.5',
    'Ubuntu 22.04',
    'Android 12',
    'iOS 16.5',
    'Chrome Browser',
    'Firefox Browser',
    'Edge Browser'
]

# Sources
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


def generate_email(domain, first_name, last_name, index):
    """Generate email address"""
    patterns = [
        f"{first_name}.{last_name}@{domain}",
        f"{first_name}{last_name}@{domain}",
        f"{first_name}{index}@{domain}",
        f"{last_name}.{first_name}@{domain}",
        f"{first_name[0]}{last_name}@{domain}",
    ]
    return random.choice(patterns).lower()


def generate_ip_address():
    """Generate random IP address"""
    base = random.choice(IP_RANGES)
    last_octet = random.randint(1, 254)
    return f"{base}{last_octet}"


def generate_date_range(days_back=90):
    """Generate random date within range"""
    start_date = date.today() - timedelta(days=days_back)
    end_date = date.today()
    days_between = (end_date - start_date).days
    random_days = random.randint(0, days_between)
    return start_date + timedelta(days=random_days)


def create_demo_data():
    """Create demo data for companies and breached credentials"""
    with app.app_context():
        # Get or create admin user for created_by field
        admin_user = User.query.filter_by(role='admin').first()
        if not admin_user:
            # Create a default admin user if none exists
            admin_user = User(
                username='admin',
                email='admin@dseclab.com',
                role='admin',
                isAdmin=True,
                is_active=True
            )
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            db.session.commit()
            print("Created admin user for demo data")

        companies_created = []
        
        # Create companies and their breached credentials
        for company_data in COMPANIES:
            # Get or create company
            company = Company.query.filter_by(domain=company_data['domain']).first()
            if not company:
                company = Company(
                    name=company_data['name'],
                    domain=company_data['domain'],
                    company_type=company_data['company_type'],
                    description=f"Demo company: {company_data['name']}"
                )
                db.session.add(company)
                db.session.commit()
                print(f"✓ Created company: {company_data['name']} ({company_data['domain']})")
            else:
                print(f"✓ Company already exists: {company_data['name']} ({company_data['domain']})")
            
            companies_created.append(company)
            
            # Create 20 breached credentials for this company
            existing_count = BreachedCredential.query.filter_by(domain=company.domain).count()
            needed = 20 - existing_count
            
            if needed > 0:
                print(f"  Creating {needed} breached credentials for {company.domain}...")
                
                for i in range(needed):
                    # Random data generation
                    first_name = random.choice(FIRST_NAMES)
                    last_name = random.choice(LAST_NAMES)
                    leak_type = random.choice(LEAK_TYPES)
                    source = random.choice(SOURCES)
                    
                    # Generate username (can be email format or just username)
                    if random.random() > 0.5:  # 50% chance of email format
                        username = generate_email(company.domain, first_name, last_name, i)
                    else:
                        username = f"{first_name.lower()}{random.randint(1, 999)}"
                    
                    # Generate domain (use company domain or random domain)
                    domain = company.domain
                    if random.random() > 0.8:  # 20% chance of different domain
                        domain = random.choice(['example.com', 'test.com', 'demo.org'])
                    
                    # Generate password (30% chance of having password)
                    password = None
                    if random.random() > 0.7:
                        password = f"Pass{random.randint(1000, 9999)}!"
                    
                    # Generate URL (40% chance)
                    url = None
                    if random.random() > 0.6:
                        url = f"https://{random.choice(['pastebin.com', 'github.com', 'example.com'])}/leak/{random.randint(1000, 9999)}"
                    
                    # Generate _id, _index, _score (Elasticsearch-like fields)
                    _id = f"breach_{company.domain}_{i}_{random.randint(10000, 99999)}"
                    _index = random.choice(['breaches-2024', 'leaks-2024', 'credentials-2024'])
                    _score = round(random.uniform(0.5, 10.0), 2) if random.random() > 0.3 else None
                    _ignored = random.random() > 0.9  # 10% chance of being ignored
                    
                    # Create breached credential with new field structure
                    credential = BreachedCredential(
                        _id=_id,
                        _index=_index,
                        _score=_score,
                        _ignored=_ignored,
                        username=username,
                        domain=domain,
                        password=password,
                        source=source,
                        type=leak_type,
                        url=url,
                        is_marked=random.random() > 0.7,  # 30% chance of being marked
                        company_id=company.id,
                        created_by=admin_user.id
                    )
                    
                    db.session.add(credential)
                
                db.session.commit()
                print(f"  ✓ Created {needed} breached credentials for {company.domain}")
            else:
                print(f"  ✓ Already have 20+ credentials for {company.domain}")
        
        # Summary
        print("\n" + "="*50)
        print("Demo Data Creation Summary:")
        print("="*50)
        for company in companies_created:
            count = BreachedCredential.query.filter_by(domain=company.domain).count()
            print(f"  {company.name} ({company.domain}): {count} credentials")
        
        total_creds = BreachedCredential.query.count()
        total_companies = Company.query.count()
        print(f"\nTotal Companies: {total_companies}")
        print(f"Total Breached Credentials: {total_creds}")
        print("="*50)
        print("\n✓ Demo data creation completed!")


if __name__ == '__main__':
    create_demo_data()

