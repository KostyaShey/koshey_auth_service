"""
Database instance and configuration.

This module provides the shared SQLAlchemy database instance to avoid circular imports
between app.py and models.
"""

from flask_sqlalchemy import SQLAlchemy

# Shared database instance
db = SQLAlchemy()
