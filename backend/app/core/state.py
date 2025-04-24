from collections import deque
import logging
from typing import Dict, Any, Optional, Deque
from datetime import datetime

from config.settings import TZ

logger = logging.getLogger(__name__)

class AppState:
    """
    Centralized application state management.
    Handles state sharing between components and event processing.
    """
    
    def __init__(self):
        # Elasticsearch client
        self.es_client = None
        
        # Security monitor
        self.security_monitor = None
        
        # Monitoring state
        self.monitoring_active = False
        self.monitor_thread = None
        
        # In-memory storage
        self.log_queue: Deque[Dict] = deque(maxlen=1000)  # Store last 1000 log entries
        self.recent_alerts: Deque[Dict] = deque(maxlen=50)  # Store last 50 alerts
        
        # Connected clients
        self.clients: Dict[str, Deque] = {}  # client_id -> queue
    
    def handle_alert(self, alert_data: Dict[str, Any]):
        """
        Process a new alert.
        
        Args:
            alert_data: Alert data to process
        """
        # Add to recent alerts
        self.recent_alerts.appendleft(alert_data)
        
        # Log the alert
        logger.warning(f"{alert_data['type']}: Agent {alert_data['agent_id']} - {alert_data['description']}")
        
        # Send to SSE clients
        self._send_to_clients("alert", alert_data)
    
    def handle_stats(self, stats_data: Dict[str, int]):
        """
        Process updated statistics.
        
        Args:
            stats_data: Updated statistics data
        """
        # Send to SSE clients
        self._send_to_clients("stats", stats_data)
    
    def handle_raw_alerts(self, alerts: list):
        """
        Process raw alert data for advanced users.
        
        Args:
            alerts: List of raw alert data
        """
        # Send to SSE clients
        self._send_to_clients("raw_alerts", alerts)
    
    def _send_to_clients(self, event_type: str, data: Any):
        """
        Send an event to all connected clients.
        
        Args:
            event_type: Type of event
            data: Event data
        """
        for client_id, client_queue in list(self.clients.items()):
            try:
                client_queue.append((event_type, data))
            except Exception as e:
                logger.error(f"Error sending to client {client_id}: {str(e)}")
                self.clients.pop(client_id, None)


# Create global application state
app_state = AppState()


# Custom handler for logs to store in our queue
class QueueHandler(logging.Handler):
    """Custom logging handler that stores logs in the application state queue."""
    
    def __init__(self, log_queue):
        logging.Handler.__init__(self)
        self.log_queue = log_queue
        
    def emit(self, record):
        try:
            log_entry = {
                "timestamp": datetime.now(tz=TZ).isoformat(),
                "level": record.levelname.lower(),
                "message": self.format(record)
            }
            self.log_queue.append(log_entry)
            
            # Send to SSE clients
            for client_id, client_queue in list(app_state.clients.items()):
                try:
                    client_queue.append(("log", {
                        "level": log_entry["level"],
                        "message": log_entry["message"]
                    }))
                except Exception:
                    app_state.clients.pop(client_id, None)
        except Exception as e:
            # Avoid infinite recursion if there's an error in the handler
            print(f"Error in QueueHandler: {str(e)}")


def configure_queue_logging():
    """Configure logging to use the queue handler."""
    # Set up the queue handler
    queue_handler = QueueHandler(app_state.log_queue)
    queue_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(message)s')
    queue_handler.setFormatter(formatter)
    
    # Add to root logger
    root_logger = logging.getLogger()
    root_logger.addHandler(queue_handler)
    
    # Add to app logger
    app_logger = logging.getLogger('app')
    app_logger.addHandler(queue_handler)
    
    # Add to security logger
    security_logger = logging.getLogger('security')
    security_logger.addHandler(queue_handler)