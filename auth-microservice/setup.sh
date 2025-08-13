#!/bin/bash

# Auth Microservice Setup Script
# This script helps you set up the authentication microservice

set -e

echo "🔐 Auth Microservice Setup"
echo "=========================="

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Docker and Docker Compose are installed"

# Create .env file from template if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env
    echo "⚠️  Please edit .env file with your configuration before starting services!"
    echo "   Especially change SECRET_KEY and JWT_SECRET_KEY for production!"
else
    echo "✅ .env file already exists"
fi

# Ask user what they want to do
echo ""
echo "What would you like to do?"
echo "1. Start services (production mode)"
echo "2. Start services with development tools"
echo "3. Generate production secrets"
echo "4. Just build images"
echo "5. Stop services"
echo "6. View logs"

read -p "Enter your choice (1-6): " choice

case $choice in
    1)
        echo "🚀 Starting services in production mode..."
        docker-compose up -d
        echo "✅ Services started!"
        echo "   - API: http://localhost:5000"
        echo "   - Health check: http://localhost:5000/health"
        ;;
    2)
        echo "🚀 Starting services with development tools..."
        docker-compose --profile dev up -d
        echo "✅ Services started!"
        echo "   - API: http://localhost:5000"
        echo "   - Health check: http://localhost:5000/health"
        echo "   - pgAdmin: http://localhost:8080 (admin@authservice.com / admin)"
        echo "   - Redis Commander: http://localhost:8081"
        ;;
    3)
        echo "🔑 Generating production secrets..."
        if [ -f scripts/generate_keys.py ]; then
            python3 scripts/generate_keys.py
        else
            echo "❌ Key generation script not found"
        fi
        ;;
    4)
        echo "🔨 Building Docker images..."
        docker-compose build
        echo "✅ Images built successfully!"
        ;;
    5)
        echo "🛑 Stopping services..."
        docker-compose down
        echo "✅ Services stopped!"
        ;;
    6)
        echo "📋 Viewing logs..."
        docker-compose logs -f auth-service
        ;;
    *)
        echo "❌ Invalid choice"
        exit 1
        ;;
esac

# Show service status
echo ""
echo "📊 Service Status:"
docker-compose ps

# Show useful commands
echo ""
echo "💡 Useful commands:"
echo "   Check health: curl http://localhost:5000/health"
echo "   View logs: docker-compose logs -f auth-service"
echo "   Stop services: docker-compose down"
echo "   Restart: docker-compose restart auth-service"
echo ""
echo "📚 For more information, see README.md"
