#!/usr/bin/env python
"""
Script to clear all breached credential data
"""
from cuba import app, db
from cuba.models import BreachedCredential

def clear_breached_data():
    """Clear all breached credential data"""
    with app.app_context():
        count = BreachedCredential.query.count()
        print(f"Found {count} breached credentials to delete...")
        
        if count > 0:
            BreachedCredential.query.delete()
            db.session.commit()
            print(f"✓ Deleted {count} breached credentials")
        else:
            print("✓ No breached credentials to delete")
        
        print("\n✓ Breached data cleared successfully!")

if __name__ == '__main__':
    clear_breached_data()

