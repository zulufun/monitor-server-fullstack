from datetime import datetime, timedelta
import time
import logging
import json
from typing import List, Dict, Optional, Any

from elasticsearch import Elasticsearch
from .elasticsearch_client import get_wazuh_alerts
from .matching import (
    filter_bypassuac_attempt, 
    filter_malicious_shell_connect, 
    filter_lsass_access_attempt
)

from datetime import timedelta, timezone
tz = timezone(timedelta(hours=7))

# Configure logging
logger = logging.getLogger(__name__)


class SecurityMonitor:
    """
    Real-time security monitoring service that detects security threats
    by analyzing Wazuh alerts from Elasticsearch.
    """
    
    def __init__(self, 
                 es_client: Elasticsearch, 
                 index: str = "wazuh-alerts-*", 
                 interval: int = 3,
                 agent_id: Optional[str] = None,
                 start_time: Optional[datetime] = None,
                 window_size: int = 5):
        """
        Initialize the security monitor.
        
        Args:
            es_client: Elasticsearch client
            index: Elasticsearch index to query
            interval: How often to check for new alerts (in seconds)
            agent_id: Optional agent ID to filter results
            start_time: Optional specific start time to begin monitoring from
            window_size: Size of the time window in seconds (default: 5)
        """
        self.es_client = es_client
        self.index = index
        self.interval = interval
        self.agent_id = agent_id
        self.window_size = window_size  # Fixed window size in seconds
        
        # Use provided start time or default to current time minus interval
        if start_time:
            start_time = start_time.replace(tzinfo=tz)
            self.current_window_start = start_time
            logger.info(f"Starting monitoring from specific time: {start_time.isoformat()}")
        else:
            self.current_window_start = datetime.now(tz=tz) - timedelta(seconds=interval)
            logger.info(f"Starting monitoring from {interval} seconds ago")
        
        # Calculate the end of the first window
        self.current_window_end = self.current_window_start + timedelta(seconds=window_size)
        
        # Track alert counts for reporting
        self.alert_counters = {
            "total": 0,
            "bypassuac": 0,
            "malicious_shell": 0,
            "credential_access": 0
        }
    
    def get_additional_filters(self) -> List[Dict]:
        """Generate additional filters based on configuration"""
        filters = []
        
        if self.agent_id:
            filters.append({"term": {"agent.id": self.agent_id}})
            
        return filters
    
    def process_alerts(self, alerts: List[Dict]) -> None:
        """
        Process alerts through all detection filters
        
        Args:
            alerts: List of alerts to process
        """
        if not alerts:
            return
            
        self.alert_counters["total"] += len(alerts)
        
        # Process alerts through specialized filters
        self._process_bypassuac_alerts(alerts)
        self._process_malicious_shell_alerts(alerts)
        self._process_lsass_access_alerts(alerts)
    
    def _process_bypassuac_alerts(self, alerts):
        """Process alerts through UAC bypass filter"""
        bypassuac_alerts = filter_bypassuac_attempt(alerts)
        if bypassuac_alerts:
            self.alert_counters["bypassuac"] += len(bypassuac_alerts)
            logger.warning(f"Detected {len(bypassuac_alerts)} UAC bypass attempts!")
            for alert in bypassuac_alerts:
                logger.warning(f"UAC Bypass: Agent {alert.get('agent', {}).get('id', 'unknown')} - {alert.get('rule', {}).get('description', 'No description')}")
                # Log the full alert details
                logger.info(f"Full UAC Bypass Alert: {json.dumps(alert, indent=2)}")
    
    def _process_malicious_shell_alerts(self, alerts):
        """Process alerts through malicious shell filter"""
        shell_alerts = filter_malicious_shell_connect(alerts)
        if shell_alerts:
            self.alert_counters["malicious_shell"] += len(shell_alerts)
            logger.warning(f"Detected {len(shell_alerts)} malicious PowerShell activities!")
            for alert in shell_alerts:
                logger.warning(f"Malicious Shell: Agent {alert.get('agent', {}).get('id', 'unknown')} - {alert.get('rule', {}).get('description', 'No description')}")
                # Log the full alert details
                logger.info(f"Full Malicious Shell Alert: {json.dumps(alert, indent=2)}")
    
    def _process_lsass_access_alerts(self, alerts):
        """Process alerts through LSASS access filter"""
        lsass_alerts = filter_lsass_access_attempt(alerts)
        if lsass_alerts:
            self.alert_counters["credential_access"] += len(lsass_alerts)
            logger.warning(f"Detected {len(lsass_alerts)} LSASS memory access attempts!")
            for alert in lsass_alerts:
                logger.warning(f"Credential Access: Agent {alert.get('agent', {}).get('id', 'unknown')} - {alert.get('rule', {}).get('description', 'No description')}")
                # Log the full alert details
                logger.info(f"Full Credential Access Alert: {json.dumps(alert, indent=2)}")
    
    def check_new_alerts(self) -> None:
        """Check for alerts in the current time window"""
        try:
            # Get alerts from the current window
            start_time = self.current_window_start.isoformat()
            end_time = self.current_window_end.isoformat()
            
            # Display the time window being monitored
            logger.info(f"Monitoring time window: {self.current_window_start.strftime('%H:%M:%S.%f')[:-3]} to "
                       f"{self.current_window_end.strftime('%H:%M:%S.%f')[:-3]} "
                       f"({self.window_size} seconds)")
            
            additional_filters = self.get_additional_filters()
            
            alerts = get_wazuh_alerts(
                es_client=self.es_client,
                start_time=start_time,
                end_time=end_time,
                size=100,  # Adjust if needed
                index=self.index,
                additional_filters=additional_filters
            )
            
            if alerts:
                logger.info(f"Retrieved {len(alerts)} alerts in window")
                self.process_alerts(alerts)
            else:
                logger.info("No alerts found in this time window")
            
            # Move to the next window
            self.current_window_start = self.current_window_end
            self.current_window_end = self.current_window_start + timedelta(seconds=self.window_size)
            
        except Exception as e:
            logger.error(f"Error checking for alerts: {str(e)}")
    
    def print_stats(self) -> None:
        """Print current detection statistics"""
        logger.info("=== Security Monitor Statistics ===")
        logger.info(f"Total alerts processed: {self.alert_counters['total']}")
        logger.info(f"UAC bypass attempts: {self.alert_counters['bypassuac']}")
        logger.info(f"Malicious PowerShell activities: {self.alert_counters['malicious_shell']}")
        logger.info(f"LSASS access attempts: {self.alert_counters['credential_access']}")
        logger.info("=================================")