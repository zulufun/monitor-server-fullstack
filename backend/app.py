#!/usr/bin/env python3
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import the app factory
from app import create_app
from config.settings import API_HOST, API_PORT, DEBUG_MODE

if __name__ == "__main__":
    # Create the application
    app = create_app()
    
    # Start the Flask application
    app.run(
        host=API_HOST, 
        port=API_PORT, 
        debug=DEBUG_MODE, 
        threaded=True
    )