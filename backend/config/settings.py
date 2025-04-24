import os
from datetime import timezone, timedelta

# API configuration
API_HOST = os.getenv('API_HOST', '0.0.0.0')
API_PORT = int(os.getenv('API_PORT', '5000'))
DEBUG_MODE = os.getenv('DEBUG_MODE', 'false').lower() == 'true'

# Elasticsearch configuration
ES_HOST = os.getenv('ES_HOST')
ES_PORT = os.getenv('ES_PORT')
ES_USER = os.getenv('ES_USER', '')
ES_PASSWORD = os.getenv('ES_PASSWORD', '')
ES_USE_SSL = os.getenv('ES_USE_SSL', 'true').lower() == 'true'

# Time zone configuration
offset = int(os.getenv('TIMEZONE_OFFSET', 0))
TZ = timezone(timedelta(hours=offset))  # UTC by default

# Monitoring configuration
DEFAULT_INDEX = os.getenv('DEFAULT_INDEX', 'wazuh-alerts-*')
DEFAULT_INTERVAL = int(os.getenv('DEFAULT_INTERVAL', '3'))
DEFAULT_WINDOW_SIZE = int(os.getenv('DEFAULT_WINDOW_SIZE', '5'))
STATS_INTERVAL = int(os.getenv('STATS_INTERVAL', '60'))  # How often to print stats (seconds)