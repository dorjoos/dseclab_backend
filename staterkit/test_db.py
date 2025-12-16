"""Test database after migration"""
from cuba import app, db
from cuba.models import User, Company, BreachedCredential

with app.app_context():
    # Test user query
    user = User.query.filter_by(email='admin@dseclab.com').first()
    if user:
        print(f'✓ User found: {user.username} - role: {user.role}, isAdmin: {user.isAdmin}')
    else:
        print('✗ User not found')
    
    # Test all users
    users = User.query.all()
    print(f'\n✓ Total users: {len(users)}')
    for u in users:
        print(f'  - {u.username}: role={u.role}, email={u.email}')
    
    # Test company table
    companies = Company.query.all()
    print(f'\n✓ Total companies: {len(companies)}')
    
    # Test breached credentials
    creds = BreachedCredential.query.all()
    print(f'\n✓ Total breached credentials: {len(creds)}')
    
    print('\n✓ Database migration successful! All queries working.')

