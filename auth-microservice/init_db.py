#!/usr/bin/env python3
"""
Database initialization script for Auth Microservice
This script properly initializes the Flask-Migrate database migrations
"""

import os
import sys
from pathlib import Path

# Add src directory to Python path
src_path = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_path))

# Set environment variables
os.environ['FLASK_APP'] = 'app'
os.environ['FLASK_ENV'] = 'development'

def init_database():
    """Initialize the database with Flask-Migrate"""
    try:
        # Import after setting up the path
        from app import create_app, db
        from flask_migrate import init, migrate, upgrade
        
        print("🔐 Initializing Auth Microservice Database")
        print("=" * 45)
        
        # Create Flask app
        app = create_app()
        
        with app.app_context():
            # Check if migrations directory exists
            migrations_dir = Path('migrations')
            
            if not migrations_dir.exists():
                print("📝 Initializing Flask-Migrate...")
                init()
                print("✅ Flask-Migrate initialized!")
            else:
                print("✅ Flask-Migrate already initialized")
            
            # Create migration
            print("📝 Creating initial migration...")
            migrate(message="Initial migration")
            print("✅ Initial migration created!")
            
            # Apply migration
            print("📝 Applying migrations to database...")
            upgrade()
            print("✅ Database migrations applied!")
            
            print("\n🎉 Database initialization completed successfully!")
            print("\n💡 Next steps:")
            print("   1. Start the application: python src/app.py")
            print("   2. Test the API: curl http://localhost:5000/health")
            
    except Exception as e:
        print(f"❌ Error during database initialization: {e}")
        print("\n🔧 Troubleshooting:")
        print("   1. Make sure PostgreSQL is running: sudo docker compose ps db")
        print("   2. Check database logs: sudo docker compose logs db")
        print("   3. Verify .env configuration")
        sys.exit(1)

if __name__ == '__main__':
    init_database()
