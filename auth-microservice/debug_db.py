#!/usr/bin/env python3
"""Debug database connectivity issues"""

import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add src to path
sys.path.append('src')

try:
    from config.settings import DATABASE_URL, REDIS_URL
    print(f"✅ Config loaded")
    print(f"DATABASE_URL: {DATABASE_URL}")
    print(f"REDIS_URL: {REDIS_URL}")
    
    # Test database connection
    from database import db
    from app import create_app
    
    app = create_app()
    
    with app.app_context():
        try:
            # This is the exact same check as in the health endpoint
            result = db.session.execute(db.text('SELECT 1'))
            print(f"✅ Database connection successful")
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            print(f"Exception type: {type(e)}")
            import traceback
            traceback.print_exc()
        
        try:
            # Test Redis connection
            import redis
            redis_client = redis.Redis.from_url(REDIS_URL)
            redis_client.ping()
            print(f"✅ Redis connection successful")
        except Exception as e:
            print(f"❌ Redis connection failed: {e}")
            
except Exception as e:
    print(f"❌ Setup failed: {e}")
    import traceback
    traceback.print_exc()
