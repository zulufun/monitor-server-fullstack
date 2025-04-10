"""Security monitoring package for Wazuh alerts."""

# Package version
__version__ = "1.0.0"

# Import main components for easier access
from .monitor import SecurityMonitor
from .elasticsearch_client import create_es_client, get_wazuh_alerts
from .matching import (
    filter_bypassuac_attempt,
    filter_malicious_shell_connect,
    filter_lsass_access_attempt
)