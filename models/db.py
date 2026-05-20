"""Single shared SQLAlchemy instance.

Kept in its own module to avoid circular imports between the model files and
the Flask app factory.
"""

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
