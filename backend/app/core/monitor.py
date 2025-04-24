from datetime import datetime, timedelta
import time
import logging
from typing import List, Dict, Optional, Any

from elasticsearch import Elasticsearch

from security.processor.alert_processor import AlertProcessor
from security.elasticsearch.client import get_wazuh_alerts

# Import configuration
from config.settings import TZ, DEFAULT_WINDOW_SIZE

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
                 window_size: int = DEFAULT_WINDOW_SIZE):
        """
        Initialize the security monitor.
        
        Args:
            es_client: Elasticsearch client
            index: Elasticsearch index to query
            interval: How often to check for new alerts (in seconds)
            agent_id: Optional agent ID to filter results
            start_time: Optional specific start time to begin monitoring from
            window_size: Size of the time window in seconds
        """
        self.es_client = es_client
        self.index = index
        self.interval = interval
        self.agent_id = agent_id
        self.window_size = window_size
        
        # Initialize alert processor
        self.alert_processor = AlertProcessor()
        
        # Use provided start time or default to current time minus interval
        if start_time:
            if start_time.tzinfo is None:
                start_time = start_time.replace(tzinfo=TZ)
            self.current_window_start = start_time
            logger.info(f"Starting monitoring from specific time: {start_time.isoformat()}")
        else:
            self.current_window_start = datetime.now(tz=TZ) - timedelta(seconds=interval)
            logger.info(f"Starting monitoring from {interval} seconds ago")
        
        # Calculate the end of the first window
        self.current_window_end = self.current_window_start + timedelta(seconds=window_size)
        
        # Set up event callbacks
        self.event_callbacks = {
            'alert': [],      # Callbacks for detected alerts
            'raw_alerts': [],  # Callbacks for raw alerts (for advanced users)
            'stats': []       # Callbacks for statistics updates
        }
    
    def get_additional_filters(self) -> List[Dict]:
        """Generate additional filters based on configuration"""
        filters = []
        
        if self.agent_id:
            filters.append({"term": {"agent.id": self.agent_id}})
            
        return filters
    
    def register_event_callback(self, event_type: str, callback_fn):
        """
        Register a callback function for a specific event type.
        
        Args:
            event_type: Type of event ('alert', 'raw_alerts', 'stats')
            callback_fn: Function to call when event occurs
        """
        if event_type in self.event_callbacks:
            self.event_callbacks[event_type].append(callback_fn)
        else:
            logger.warning(f"Unknown event type: {event_type}")
    
    def trigger_event(self, event_type: str, data: Any):
        """
        Trigger an event and call all registered callbacks.
        
        Args:
            event_type: Type of event
            data: Data to pass to callbacks
        """
        if event_type not in self.event_callbacks:
            return
            
        for callback in self.event_callbacks[event_type]:
            try:
                callback(data)
            except Exception as e:
                logger.error(f"Error in event callback: {str(e)}")
    
    def process_alerts(self, alerts: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Process alerts through detection mechanisms
        
        Args:
            alerts: List of alerts to process
            
        Returns:
            Dictionary mapping mechanism names to their detected alerts
        """
        if not alerts:
            return {}
        
        # Process alerts through the processor
        results = self.alert_processor.process_alerts(alerts)
        
        # Trigger stats event
        self.trigger_event('stats', self.alert_processor.get_stats())
        
        # Trigger raw_alerts event
        self.trigger_event('raw_alerts', alerts)
        
        # Trigger alert events for each detection
        for detector_name, detected_alerts in results.items():
            if not detected_alerts:
                continue
                
            # Get the detector info from the processor
            detector = self.alert_processor.detectors.get(detector_name)
            if not detector:
                continue
                
            detector_info = detector.get_info()
            alert_type = detector_info["alert_type"]
            
            # Process each alert
            for alert in detected_alerts:
                alert_data = {
                    "type": alert_type,
                    "detector": detector_name,
                    "agent_id": alert.get('agent', {}).get('id', 'unknown'),
                    "description": alert.get('rule', {}).get('description', 'No description'),
                    "timestamp": alert.get('timestamp', datetime.now(tz=TZ).isoformat()),
                    "full_alert": alert  # Store the full alert data
                }
                
                # Trigger the alert event
                self.trigger_event('alert', alert_data)
        
        return results
    
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
        stats = self.alert_processor.get_stats()
        
        logger.info("=== Security Monitor Statistics ===")
        logger.info(f"Total alerts processed: {stats.get('total', 0)}")
        
        # Log statistics for each registered detector
        for detector_name, detector in self.alert_processor.detectors.items():
            detector_info = detector.get_info()
            counter_key = detector_info["counter_key"]
            alert_type = detector_info["alert_type"]
            
            count = stats.get(counter_key, 0)
            logger.info(f"{alert_type}: {count}")
            
        logger.info("===================================")