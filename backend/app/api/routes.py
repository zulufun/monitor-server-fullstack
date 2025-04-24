from flask import Blueprint, jsonify, request, Response
import json
import time
import uuid
import threading
import logging
from collections import deque
from datetime import datetime, timedelta

from app.core.state import app_state
from app.core.monitor import SecurityMonitor
from security.elasticsearch.client import create_es_client
from config.settings import TZ, DEFAULT_WINDOW_SIZE, DEFAULT_INDEX, DEFAULT_INTERVAL

# Create blueprint
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Configure logging
logger = logging.getLogger(__name__)

@api_bp.route('/status', methods=['GET'])
def get_status():
    """Return the current status of the monitoring service"""
    return jsonify({
        "connected": app_state.es_client is not None,
        "monitoring": app_state.monitoring_active,
        "stats": app_state.security_monitor.alert_processor.get_stats() if app_state.security_monitor else {
            "total": 0
        },
        "detectors": [
            {
                "name": detector.name,
                "type": detector.alert_type,
                "counter": detector.counter_key,
                "count": app_state.security_monitor.alert_processor.alert_counters.get(detector.counter_key, 0)
            } 
            for detector in (app_state.security_monitor.alert_processor.detectors.values() 
                             if app_state.security_monitor else [])
        ]
    })

@api_bp.route('/logs', methods=['GET'])
def get_logs():
    """Return recent logs"""
    # Convert deque to list (newest first)
    logs = list(app_state.log_queue)
    return jsonify(logs)

@api_bp.route('/alerts', methods=['GET'])
def get_alerts():
    """Return recent alerts"""
    # Convert deque to list (newest first)
    alerts = list(app_state.recent_alerts)
    return jsonify(alerts)

@api_bp.route('/connect', methods=['POST'])
def connect():
    """Connect to Elasticsearch"""
    try:
        if app_state.es_client:
            return jsonify({"success": True})
            
        app_state.es_client = create_es_client()
        
        # Test connection
        if app_state.es_client.ping():
            logger.info("Successfully connected to Elasticsearch")
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "error": "Failed to connect to Elasticsearch"})
    
    except Exception as e:
        logger.error(f"Error connecting to Elasticsearch: {str(e)}")
        return jsonify({"success": False, "error": str(e)})

@api_bp.route('/start', methods=['POST'])
def start_monitoring():
    """Start security monitoring"""
    if app_state.monitoring_active:
        return jsonify({"success": True})
        
    try:
        # Get configuration from request
        config_params = request.json or {}
        
        # Parse start time and window size if provided
        start_time = None
        if config_params.get("start_time"):
            try:
                start_time = datetime.fromisoformat(config_params.get("start_time"))
                logger.info(f"Using custom start time: {start_time.isoformat()}")
            except ValueError as e:
                logger.warning(f"Invalid start time format: {str(e)}. Using default.")
        
        # Get window size (default to config value if not specified)
        window_size = int(config_params.get("window_size", DEFAULT_WINDOW_SIZE))
        logger.info(f"Using window size of {window_size} seconds")
        
        # Create SecurityMonitor instance
        app_state.security_monitor = SecurityMonitor(
            es_client=app_state.es_client,
            index=config_params.get("index", DEFAULT_INDEX),
            interval=int(config_params.get("interval", DEFAULT_INTERVAL)),
            agent_id=config_params.get("agent_id") if config_params.get("agent_id") else None,
            start_time=start_time if start_time else datetime.now(tz=TZ) - timedelta(seconds=60),
            window_size=window_size
        )
        
        # Register event handlers
        app_state.security_monitor.register_event_callback('alert', app_state.handle_alert)
        app_state.security_monitor.register_event_callback('stats', app_state.handle_stats)
        app_state.security_monitor.register_event_callback('raw_alerts', app_state.handle_raw_alerts)
        
        # Start monitoring thread
        app_state.monitoring_active = True
        app_state.monitor_thread = threading.Thread(target=monitoring_loop)
        app_state.monitor_thread.daemon = True
        app_state.monitor_thread.start()
        
        logger.info("Monitoring started")
        return jsonify({"success": True})
    
    except Exception as e:
        logger.error(f"Error starting monitoring: {str(e)}")
        return jsonify({"success": False, "error": str(e)})

@api_bp.route('/stop', methods=['POST'])
def stop_monitoring():
    """Stop security monitoring"""
    if not app_state.monitoring_active:
        return jsonify({"success": True})
    
    try:
        app_state.monitoring_active = False
        
        # Wait for thread to terminate (with timeout)
        if app_state.monitor_thread and app_state.monitor_thread.is_alive():
            app_state.monitor_thread.join(timeout=2.0)
        
        logger.info("Monitoring stopped")
        return jsonify({"success": True})
    
    except Exception as e:
        logger.error(f"Error stopping monitoring: {str(e)}")
        return jsonify({"success": False, "error": str(e)})

@api_bp.route('/events')
def events():
    """SSE endpoint for real-time updates"""
    def generate():
        # Create a unique client ID and a new queue for this client
        client_id = str(uuid.uuid4())
        client_queue = deque(maxlen=100)
        app_state.clients[client_id] = client_queue
        
        # Send current stats if available
        if app_state.security_monitor:
            client_queue.append(("stats", app_state.security_monitor.alert_processor.get_stats()))
        
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
            app_state.clients.pop(client_id, None)
    
    return Response(generate(), mimetype='text/event-stream')

def monitoring_loop():
    """Main monitoring loop (runs in a separate thread)"""
    if not app_state.security_monitor:
        logger.error("SecurityMonitor not initialized")
        return
    
    try:
        # Run the monitor with our own loop to control termination
        logger.info(f"Starting security monitor. Checking every {app_state.security_monitor.interval} seconds")
        logger.info(f"Monitoring index: {app_state.security_monitor.index}")
        
        if app_state.security_monitor.agent_id:
            logger.info(f"Filtering for agent ID: {app_state.security_monitor.agent_id}")
            
        last_stats_time = time.time()
        stats_interval = 60  # Print stats every minute
        
        while app_state.monitoring_active:
            app_state.security_monitor.check_new_alerts()
            
            # Print stats periodically
            current_time = time.time()
            if current_time - last_stats_time >= stats_interval:
                app_state.security_monitor.print_stats()
                last_stats_time = current_time
                
            # Sleep until next check
            time.sleep(app_state.security_monitor.interval)
            
    except Exception as e:
        logger.error(f"Error in monitoring loop: {str(e)}")
    finally:
        logger.info("Monitoring loop terminated")