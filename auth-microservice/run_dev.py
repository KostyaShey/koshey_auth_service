#!/usr/bin/env python3
"""
Development server startup script for Auth Microservice
This script properly starts the Flask development server with database initialization
"""

import os
import sys
from pathlib import Path

# Add src directory to Python path
src_path = Path(__file__).parent / 'src'
sys.path.insert(0, str(src_path))

def run_dev_server():
    """Start the development server"""
    try:
        print("🔐 Starting Auth Microservice Development Server")
        print("=" * 50)
        
        # Import after setting up the path
        from app import create_app, db
        
        # Create Flask app
        app = create_app()
        
        with app.app_context():
            # Create all database tables
            print("📝 Creating database tables...")
            db.create_all()
            
            # Clean up expired tokens on startup
            print("🧹 Cleaning up expired tokens...")
            from models.user import RefreshToken
            RefreshToken.cleanup_expired()
            
            print("✅ Database initialization completed!")
        
        print(f"🚀 Starting server on http://0.0.0.0:{os.environ.get('PORT', 5000)}")
        print("💡 Press Ctrl+C to stop the server")
        print("-" * 50)
        
        # Run the application
        app.run(
            host='0.0.0.0',
            port=int(os.environ.get('PORT', 5000)),
            debug=os.environ.get('DEBUG', 'false').lower() == 'true'
        )
        
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        print("\n🔧 Troubleshooting:")
        print("   1. Make sure database is running: sudo docker compose ps db")
        print("   2. Check database initialization: python init_db.py")
        print("   3. Verify .env configuration")
        sys.exit(1)

if __name__ == '__main__':
    run_dev_server()
