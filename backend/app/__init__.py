from flask import Flask
from flask_cors import CORS
import logging

from config.settings import API_HOST, API_PORT, DEBUG_MODE
from config.logging import configure_logging
from app.core.state import configure_queue_logging
from app.api.routes import api_bp

def create_app():
    """
    Application factory function.
    Creates and configures the Flask application.
    
    Returns:
        Flask: Configured Flask application
    """
    # Configure logging
    configure_logging()
    
    # Create Flask app
    app = Flask(__name__)
    
    # Enable CORS
    CORS(app)
    
    # Configure app
    app.config['JSON_SORT_KEYS'] = False
    
    # Configure queue logging
    configure_queue_logging()
    
    # Register blueprints
    app.register_blueprint(api_bp)
    
    # Log startup message
    logger = logging.getLogger(__name__)
    logger.info("Security Monitoring API initialized")
    
    return app