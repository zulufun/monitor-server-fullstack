from datetime import datetime, timedelta
import time
import threading
import json
import logging
import uuid
from typing import Dict, List, Optional, Deque
from collections import deque

from flask import Flask, jsonify, request, Response
from flask_cors import CORS
from dotenv import load_dotenv

# Import configuration
import config

# Import the monitoring components
from security.monitor import SecurityMonitor
from security.elasticsearch_client import create_es_client
from security.matching import (
    filter_bypassuac_attempt,
    filter_malicious_shell_connect, 
    filter_lsass_access_attempt
)

# Configure logging
config.configure_logging()
logger = logging.getLogger("SecurityMonitorAPI")

# Create Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

# Global state
class MonitorState:
    def __init__(self):
        self.es_client = None
        self.security_monitor = None
        self.monitoring_active = False
        self.monitor_thread = None
        self.log_queue = deque(maxlen=1000)  # Store last 1000 log entries
        self.recent_alerts = deque(maxlen=50)  # Store last 50 alerts
        self.clients = {}  # Dictionary of client_id -> queue

state = MonitorState()

# Custom handler for logs to store in our queue
class QueueHandler(logging.Handler):
    def __init__(self, log_queue):
        logging.Handler.__init__(self)
        self.log_queue = log_queue
        
    def emit(self, record):
        log_entry = {
            "timestamp": datetime.now(tz=config.TZ).isoformat(),
            "level": record.levelname.lower(),
            "message": self.format(record)
        }
        self.log_queue.append(log_entry)
        
        # Send to SSE clients
        for client_id, client_queue in list(state.clients.items()):
            try:
                client_queue.append(("log", {
                    "level": log_entry["level"],
                    "message": log_entry["message"]
                }))
            except Exception:
                state.clients.pop(client_id, None)

# Set up the queue handler
queue_handler = QueueHandler(state.log_queue)
queue_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(message)s')
queue_handler.setFormatter(formatter)
logger.addHandler(queue_handler)
root_logger = logging.getLogger()
root_logger.addHandler(queue_handler)

# Custom alert handler class
class AlertHandler:
    def __init__(self, alert_type):
        self.alert_type = alert_type

    def __call__(self, alert):
        agent_id = alert.get('agent', {}).get('id', 'unknown')
        description = alert.get('rule', {}).get('description', 'No description')
        timestamp = alert.get('timestamp', datetime.now(tz=config.TZ).isoformat())
        
        logger.warning(f"{self.alert_type}: Agent {agent_id} - {description}")
        
        # Add to recent alerts with full alert data
        alert_data = {
            "type": self.alert_type,
            "agent_id": agent_id,
            "description": description,
            "timestamp": timestamp,
            "full_alert": alert  # Store the full alert data
        }
        
        state.recent_alerts.appendleft(alert_data)
        
        # Send to clients
        for client_id, client_queue in list(state.clients.items()):
            try:
                client_queue.append(("alert", alert_data))
            except Exception:
                state.clients.pop(client_id, None)

# API Routes
@app.route('/api/status', methods=['GET'])
def get_status():
    """Return the current status of the monitoring service"""
    return jsonify({
        "connected": state.es_client is not None,
        "monitoring": state.monitoring_active,
        "stats": state.security_monitor.alert_counters if state.security_monitor else {
            "total": 0,
            "bypassuac": 0,
            "malicious_shell": 0,
            "credential_access": 0
        }
    })

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Return recent logs"""
    # Convert deque to list (newest first)
    logs = list(state.log_queue)
    return jsonify(logs)

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Return recent alerts"""
    # Convert deque to list (newest first)
    alerts = list(state.recent_alerts)
    return jsonify(alerts)

@app.route('/api/connect', methods=['POST'])
def connect():
    """Connect to Elasticsearch"""
    try:
        if state.es_client:
            return jsonify({"success": True})
            
        state.es_client = create_es_client()
        
        # Test connection
        if state.es_client.ping():
            logger.info("Successfully connected to Elasticsearch")
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Failed to connect to Elasticsearch"})
    
    except Exception as e:
        logger.error(f"Error connecting to Elasticsearch: {str(e)}")
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/start', methods=['POST'])
def start_monitoring():
    """Start security monitoring"""
    if state.monitoring_active:
        return jsonify({"success": True})
        
    try:
        # Get configuration from request
        config_params = request.json
        
        # Parse start time and window size if provided
        start_time = None
        if config_params.get("start_time"):
            try:
                start_time = datetime.fromisoformat(config_params.get("start_time"))
                logger.info(f"Using custom start time: {start_time.isoformat()}")
            except ValueError as e:
                logger.warning(f"Invalid start time format: {str(e)}. Using default.")
        
        # Get window size (default to config value if not specified)
        window_size = int(config_params.get("window_size", config.DEFAULT_WINDOW_SIZE))
        logger.info(f"Using window size of {window_size} seconds")
        
        # Create SecurityMonitor instance
        state.security_monitor = SecurityMonitor(
            es_client=state.es_client,
            index=config_params.get("index", config.DEFAULT_INDEX),
            interval=int(config_params.get("interval", config.DEFAULT_INTERVAL)),
            agent_id=config_params.get("agent_id") if config_params.get("agent_id") else None,
            start_time=start_time if start_time else datetime.now(tz=config.TZ) - timedelta(seconds=60),
            window_size=window_size
        )
        
        # Start monitoring thread
        state.monitoring_active = True
        state.monitor_thread = threading.Thread(target=monitoring_loop)
        state.monitor_thread.daemon = True
        state.monitor_thread.start()
        
        logger.info("Monitoring started")
        return jsonify({"success": True})
    
    except Exception as e:
        logger.error(f"Error starting monitoring: {str(e)}")
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/stop', methods=['POST'])
def stop_monitoring():
    """Stop security monitoring"""
    if not state.monitoring_active:
        return jsonify({"success": True})
    
    try:
        state.monitoring_active = False
        
        # Wait for thread to terminate (with timeout)
        if state.monitor_thread and state.monitor_thread.is_alive():
            state.monitor_thread.join(timeout=2.0)
        
        logger.info("Monitoring stopped")
        return jsonify({"success": True})
    
    except Exception as e:
        logger.error(f"Error stopping monitoring: {str(e)}")
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/events')
def events():
    """SSE endpoint for real-time updates"""
    def generate():
        # Create a unique client ID and a new queue for this client
        client_id = str(uuid.uuid4())
        client_queue = deque(maxlen=100)
        state.clients[client_id] = client_queue
        
        # Send current stats
        if state.security_monitor:
            client_queue.append(("stats", state.security_monitor.alert_counters))
        
        try:
            while True:
                # Check if there's anything in the queue
                if client_queue:
                    event_type, data = client_queue.popleft()
                    yield f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
                else:
                    # Send a heartbeat every 15 seconds
                    yield f"event: heartbeat\ndata: {{}}\n\n"
                    
                time.sleep(0.1)
        except GeneratorExit:
            # Clean up when the client disconnects
            state.clients.pop(client_id, None)
    
    return Response(generate(), mimetype='text/event-stream')

def monitoring_loop():
    """Main monitoring loop (runs in a separate thread)"""
    if not state.security_monitor:
        logger.error("SecurityMonitor not initialized")
        return
        
    # Register alert handlers to capture alerts for the web interface
    uac_handler = AlertHandler("UAC Bypass")
    shell_handler = AlertHandler("Malicious PowerShell")
    lsass_handler = AlertHandler("Credential Access")
    
    # Override the process_alerts method to send stats to clients
    original_process_alerts = state.security_monitor.process_alerts
    
    def process_alerts_with_web_updates(alerts):
        # Call the original method first
        original_process_alerts(alerts)
        
        # Send updated stats to all clients
        for client_id, client_queue in list(state.clients.items()):
            try:
                client_queue.append(("stats", state.security_monitor.alert_counters))
            except Exception:
                state.clients.pop(client_id, None)
                
        # Handle specific alert types for web interface
        bypassuac_alerts = filter_bypassuac_attempt(alerts)
        for alert in bypassuac_alerts:
            uac_handler(alert)
            
        shell_alerts = filter_malicious_shell_connect(alerts)
        for alert in shell_alerts:
            shell_handler(alert)
            
        lsass_alerts = filter_lsass_access_attempt(alerts)
        for alert in lsass_alerts:
            lsass_handler(alert)
            
        # Also send raw alerts for advanced users
        for client_id, client_queue in list(state.clients.items()):
            try:
                if alerts:
                    client_queue.append(("raw_alerts", alerts))
            except Exception:
                state.clients.pop(client_id, None)
    
    # Replace the process_alerts method
    state.security_monitor.process_alerts = process_alerts_with_web_updates
    
    try:
        # Run the monitor with our own loop to control termination
        logger.info(f"Starting security monitor. Checking every {state.security_monitor.interval} seconds")
        logger.info(f"Monitoring index: {state.security_monitor.index}")
        
        if state.security_monitor.agent_id:
            logger.info(f"Filtering for agent ID: {state.security_monitor.agent_id}")
            
        last_stats_time = time.time()
        stats_interval = config.STATS_INTERVAL  # Use config value
        
        while state.monitoring_active:
            state.security_monitor.check_new_alerts()
            
            # Print stats periodically
            current_time = time.time()
            if current_time - last_stats_time >= stats_interval:
                state.security_monitor.print_stats()
                last_stats_time = current_time
                
            # Sleep until next check
            time.sleep(state.security_monitor.interval)
            
    except Exception as e:
        logger.error(f"Error in monitoring loop: {str(e)}")
    finally:
        logger.info("Monitoring loop terminated")

if __name__ == "__main__":
    # Load environment variables
    load_dotenv()
    
    # Start the Flask application
    app.run(host=config.API_HOST, port=config.API_PORT, debug=config.DEBUG_MODE, threaded=True)