"""Configuration settings for the Security Monitor backend."""

import os
from typing import Dict, Any
import logging
from datetime import timezone, timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# API Configuration
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "5000"))
DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() == "true"

# Elasticsearch Configuration
ES_HOST = os.getenv("ES_HOST", "localhost")
ES_PORT = os.getenv("ES_PORT", "9200")
ES_USER = os.getenv("ES_USER", "")
ES_PASSWORD = os.getenv("ES_PASSWORD", "")
ES_USE_SSL = os.getenv("ES_USE_SSL", "true").lower() == "true"

# Timezone Configuration
TIMEZONE_OFFSET = int(os.getenv("TIMEZONE_OFFSET", "0"))  # Default to UTC
TZ = timezone(timedelta(hours=TIMEZONE_OFFSET))

# Monitoring Configuration
DEFAULT_INDEX = os.getenv("DEFAULT_INDEX", "wazuh-alerts-*")
DEFAULT_INTERVAL = int(os.getenv("DEFAULT_INTERVAL", "1"))
DEFAULT_WINDOW_SIZE = int(os.getenv("DEFAULT_WINDOW_SIZE", "5"))
STATS_INTERVAL = int(os.getenv("STATS_INTERVAL", "60"))  # Print stats every minute

# Logging Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", "security_monitor.log")


# Configure the logging level based on the environment
def configure_logging():
    """Configure the logging system based on environment settings."""
    numeric_level = getattr(logging, LOG_LEVEL.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler(LOG_FILE)],
    )


# Get full configuration as dictionary
def get_config() -> Dict[str, Any]:
    """Return the full configuration as a dictionary."""
    return {
        "api": {"host": API_HOST, "port": API_PORT, "debug": DEBUG_MODE},
        "elasticsearch": {
            "host": ES_HOST,
            "port": ES_PORT,
            "user": ES_USER,
            "password": ES_PASSWORD,
            "use_ssl": ES_USE_SSL,
        },
        "timezone": {
            "offset": TIMEZONE_OFFSET,
            "tz": TZ,
        },
        "monitoring": {
            "default_index": DEFAULT_INDEX,
            "default_interval": DEFAULT_INTERVAL,
            "default_window_size": DEFAULT_WINDOW_SIZE,
            "stats_interval": STATS_INTERVAL,
        },
        "logging": {"level": LOG_LEVEL, "file": LOG_FILE},
    }
    
if __name__ == "__main__":
    print(get_config())