from flask import Blueprint, jsonify, request
import logging
from datetime import datetime, timedelta

from app.core.state import app_state
from app.core.monitor import SecurityMonitor
from security.elasticsearch.client import create_es_client, get_wazuh_alerts
from config.settings import TZ, DEFAULT_WINDOW_SIZE, DEFAULT_INDEX, DEFAULT_INTERVAL

# Create blueprint
agents_bp = Blueprint('agents', __name__, url_prefix='/api/agents')

# Configure logging
logger = logging.getLogger(__name__)

@agents_bp.route('', methods=['GET'])
def get_agents():
    """
    Get a list of all available agents.
    
    Returns:
        JSON response with list of agents and their basic information
    """
    try:
        # Check if connected to Elasticsearch
        if not app_state.es_client:
            return jsonify({"success": False, "error": "Not connected to Elasticsearch"}), 400
            
        # Query Elasticsearch for distinct agent IDs
        # This uses aggregation to get unique agent IDs and names
        query = {
            "size": 0,  # We only want the aggregation results
            "aggs": {
                "agents": {
                    "terms": {
                        "field": "agent.id",
                        "size": 1000  # Limit to 1000 agents
                    },
                    "aggs": {
                        "name": {
                            "terms": {
                                "field": "agent.name",
                                "size": 1
                            }
                        },
                        "ip": {
                            "terms": {
                                "field": "agent.ip",
                                "size": 1
                            }
                        },
                        "latest_timestamp": {
                            "max": {
                                "field": "timestamp"
                            }
                        },
                        "alert_count": {
                            "value_count": {
                                "field": "_id"
                            }
                        },
                        "os": {
                            "terms": {
                                "field": "agent.os.name",
                                "size": 1
                            }
                        },
                        "version": {
                            "terms": {
                                "field": "agent.version",
                                "size": 1
                            }
                        }
                    }
                }
            }
        }
        
        try:
            result = app_state.es_client.search(index=DEFAULT_INDEX, body=query)
            buckets = result["aggregations"]["agents"]["buckets"]
        except Exception as e:
            logger.error(f"Error querying Elasticsearch for agents: {str(e)}")
            return jsonify({"success": False, "error": str(e)}), 500
            
        # Process the aggregation results
        agents = []
        for bucket in buckets:
            agent_id = bucket["key"]
            
            # Get the agent name (first bucket from the name aggregation)
            name_buckets = bucket["name"]["buckets"]
            agent_name = name_buckets[0]["key"] if name_buckets else "Unknown"
            
            # Get the agent IP (first bucket from the ip aggregation)
            ip_buckets = bucket["ip"]["buckets"]
            agent_ip = ip_buckets[0]["key"] if ip_buckets else "Unknown"
            
            # Get the latest timestamp
            latest_timestamp = bucket["latest_timestamp"]["value_as_string"] if "value_as_string" in bucket["latest_timestamp"] else None
            
            # Determine status based on timestamp (disconnected if no activity in last hour)
            status = "active"
            if latest_timestamp:
                try:
                    last_seen = datetime.fromisoformat(latest_timestamp.replace('Z', '+00:00'))
                    now = datetime.now(TZ)
                    if (now - last_seen) > timedelta(hours=1):
                        status = "disconnected"
                except Exception as e:
                    logger.error(f"Error parsing timestamp: {str(e)}")
                    status = "unknown"
            else:
                status = "unknown"
                
            # Get alert count
            alert_count = bucket["alert_count"]["value"]
            
            # Get OS information
            os_buckets = bucket["os"]["buckets"]
            os = os_buckets[0]["key"] if os_buckets else "Unknown"
            
            # Get agent version
            version_buckets = bucket["version"]["buckets"]
            version = version_buckets[0]["key"] if version_buckets else "Unknown"
            
            # Check if this agent is currently being monitored
            is_monitored = False
            if app_state.security_monitor and app_state.security_monitor.agent_id == agent_id:
                is_monitored = True
            
            # Add agent to the list
            agents.append({
                "id": agent_id,
                "name": agent_name,
                "ip": agent_ip,
                "status": status,
                "alertCount": alert_count,
                "os": os,
                "version": version,
                "lastSeen": latest_timestamp,
                "monitoring": is_monitored
            })
            
        return jsonify(agents)
        
    except Exception as e:
        logger.error(f"Error in get_agents: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@agents_bp.route('/<agent_id>', methods=['GET'])
def get_agent_details(agent_id):
    """
    Get detailed information about a specific agent.
    
    Args:
        agent_id: Agent ID
        
    Returns:
        JSON response with agent details
    """
    try:
        # Check if connected to Elasticsearch
        if not app_state.es_client:
            return jsonify({"success": False, "error": "Not connected to Elasticsearch"}), 400
            
        # Query Elasticsearch for agent details
        query = {
            "query": {
                "term": {
                    "agent.id": agent_id
                }
            },
            "size": 1,
            "sort": [
                {
                    "timestamp": {
                        "order": "desc"
                    }
                }
            ],
            "_source": ["agent", "timestamp"]
        }
        
        try:
            result = app_state.es_client.search(index=DEFAULT_INDEX, body=query)
            hits = result["hits"]["hits"]
        except Exception as e:
            logger.error(f"Error querying Elasticsearch for agent details: {str(e)}")
            return jsonify({"success": False, "error": str(e)}), 500
            
        if not hits:
            return jsonify({"success": False, "error": "Agent not found"}), 404
            
        # Get agent info from the latest document
        agent_info = hits[0]["_source"]["agent"]
        timestamp = hits[0]["_source"]["timestamp"]
        
        # Determine status based on timestamp (disconnected if no activity in last hour)
        status = "active"
        try:
            last_seen = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            now = datetime.now(TZ)
            if (now - last_seen) > timedelta(hours=1):
                status = "disconnected"
        except Exception as e:
            logger.error(f"Error parsing timestamp: {str(e)}")
            status = "unknown"
        
        # Get alert statistics
        alert_stats = {}
        try:
            # Query for alert count by rule.level
            stats_query = {
                "query": {
                    "term": {
                        "agent.id": agent_id
                    }
                },
                "size": 0,
                "aggs": {
                    "rule_levels": {
                        "terms": {
                            "field": "rule.level",
                            "size": 15
                        }
                    },
                    "alert_count": {
                        "value_count": {
                            "field": "_id"
                        }
                    },
                    "by_detector": {
                        "terms": {
                            "field": "rule.groups",
                            "size": 20
                        }
                    }
                }
            }
            
            stats_result = app_state.es_client.search(index=DEFAULT_INDEX, body=stats_query)
            
            # Get total alert count
            alert_stats["total"] = stats_result["aggregations"]["alert_count"]["value"]
            
            # Get counts by rule level
            level_buckets = stats_result["aggregations"]["rule_levels"]["buckets"]
            alert_stats["byLevel"] = {str(bucket["key"]): bucket["doc_count"] for bucket in level_buckets}
            
            # Get counts by detector/rule group
            detector_buckets = stats_result["aggregations"]["by_detector"]["buckets"]
            alert_stats["byDetector"] = {bucket["key"]: bucket["doc_count"] for bucket in detector_buckets}
            
        except Exception as e:
            logger.error(f"Error getting alert statistics: {str(e)}")
            alert_stats = {"total": 0, "byLevel": {}, "byDetector": {}}
        
        # Check if this agent is currently being monitored
        is_monitored = False
        if app_state.security_monitor and app_state.security_monitor.agent_id == agent_id:
            is_monitored = True
            
        # Combine all information
        agent_details = {
            "id": agent_id,
            "name": agent_info.get("name", "Unknown"),
            "ip": agent_info.get("ip", "Unknown"),
            "status": status,
            "lastSeen": timestamp,
            "os": agent_info.get("os", {}).get("name", "Unknown"),
            "osVersion": agent_info.get("os", {}).get("version", "Unknown"),
            "version": agent_info.get("version", "Unknown"),
            "monitoring": is_monitored,
            "alertStats": alert_stats,
            # Include any additional fields from agent_info that might be useful
            "labels": agent_info.get("labels", {}),
            "groups": agent_info.get("groups", []),
            "manager": agent_info.get("manager", {}).get("name", "Unknown")
        }
        
        return jsonify(agent_details)
        
    except Exception as e:
        logger.error(f"Error in get_agent_details: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@agents_bp.route('/<agent_id>/alerts', methods=['GET'])
def get_agent_alerts(agent_id):
    """
    Get alerts for a specific agent with optional filtering.
    
    Args:
        agent_id: Agent ID
        
    Query Parameters:
        start_time: ISO format start time
        end_time: ISO format end time
        min_level: Minimum alert level
        rule_group: Filter by rule group
        limit: Maximum number of alerts to return
        
    Returns:
        JSON response with list of alerts
    """
    try:
        # Check if connected to Elasticsearch
        if not app_state.es_client:
            return jsonify({"success": False, "error": "Not connected to Elasticsearch"}), 400
            
        # Get query parameters
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')
        min_level = request.args.get('min_level')
        rule_group = request.args.get('rule_group')
        limit = int(request.args.get('limit', 100))
        
        # Set default time range if not provided
        if not start_time:
            start_time = (datetime.now(TZ) - timedelta(days=7)).isoformat()
        if not end_time:
            end_time = datetime.now(TZ).isoformat()
            
        # Build query filters
        filters = [
            {"term": {"agent.id": agent_id}},
            {"range": {"timestamp": {"gte": start_time, "lte": end_time}}}
        ]
        
        # Add min_level filter if provided
        if min_level:
            filters.append({"range": {"rule.level": {"gte": int(min_level)}}})
            
        # Add rule_group filter if provided
        if rule_group:
            filters.append({"term": {"rule.groups": rule_group}})
            
        # Build full query
        query = {
            "query": {
                "bool": {
                    "must": filters
                }
            },
            "size": limit,
            "sort": [
                {
                    "timestamp": {
                        "order": "desc"
                    }
                }
            ]
        }
        
        try:
            # Execute query
            result = app_state.es_client.search(index=DEFAULT_INDEX, body=query)
            hits = result["hits"]["hits"]
        except Exception as e:
            logger.error(f"Error querying Elasticsearch for agent alerts: {str(e)}")
            return jsonify({"success": False, "error": str(e)}), 500
            
        # Process results
        alerts = []
        for hit in hits:
            source = hit["_source"]
            
            # Create a standardized alert object
            alert = {
                "id": hit["_id"],
                "timestamp": source.get("timestamp"),
                "agent_id": agent_id,
                "rule": {
                    "id": source.get("rule", {}).get("id"),
                    "description": source.get("rule", {}).get("description"),
                    "level": source.get("rule", {}).get("level"),
                    "groups": source.get("rule", {}).get("groups", [])
                },
                "full_log": source.get("full_log"),
                "data": source.get("data", {})
            }
            
            alerts.append(alert)
            
        return jsonify(alerts)
        
    except Exception as e:
        logger.error(f"Error in get_agent_alerts: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@agents_bp.route('/<agent_id>/logs', methods=['GET'])
def get_agent_logs(agent_id):
    """
    Get logs for a specific agent with optional filtering.
    
    Args:
        agent_id: Agent ID
        
    Query Parameters:
        level: Log level filter
        limit: Maximum number of logs to return
        
    Returns:
        JSON response with list of logs
    """
    try:
        # Filter the global log queue for this agent's logs
        level = request.args.get('level')
        limit = int(request.args.get('limit', 100))
        
        # Create a filtered copy of logs that mention this agent
        filtered_logs = []
        for log in app_state.log_queue:
            if agent_id in log.get("message", ""):
                # If level filter is applied, check the log level
                if level and log.get("level") != level:
                    continue
                filtered_logs.append(log)
                
                # Stop once we reach the limit
                if len(filtered_logs) >= limit:
                    break
                    
        return jsonify(filtered_logs)
        
    except Exception as e:
        logger.error(f"Error in get_agent_logs: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@agents_bp.route('/<agent_id>/stats', methods=['GET'])
def get_agent_stats(agent_id):
    """
    Get statistics for a specific agent.
    
    Args:
        agent_id: Agent ID
        
    Returns:
        JSON response with agent statistics
    """
    try:
        # Check if connected to Elasticsearch
        if not app_state.es_client:
            return jsonify({"success": False, "error": "Not connected to Elasticsearch"}), 400
            
        # Query for alert trends over time
        time_range = request.args.get('timeRange', '7d')  # Default to 7 days
        
        # Map time_range to an actual time period
        now = datetime.now(TZ)
        if time_range == '24h':
            start_time = (now - timedelta(hours=24)).isoformat()
            interval = '1h'  # 1-hour intervals
        elif time_range == '7d':
            start_time = (now - timedelta(days=7)).isoformat()
            interval = '1d'  # 1-day intervals
        elif time_range == '30d':
            start_time = (now - timedelta(days=30)).isoformat()
            interval = '1d'  # 1-day intervals
        else:
            start_time = (now - timedelta(days=7)).isoformat()
            interval = '1d'  # Default to 1-day intervals
            
        # Query for alert trends
        trends_query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent.id": agent_id}},
                        {"range": {"timestamp": {"gte": start_time}}}
                    ]
                }
            },
            "size": 0,
            "aggs": {
                "alerts_over_time": {
                    "date_histogram": {
                        "field": "timestamp",
                        "calendar_interval": interval,
                        "format": "yyyy-MM-dd HH:mm:ss"
                    },
                    "aggs": {
                        "by_level": {
                            "terms": {
                                "field": "rule.level",
                                "size": 15
                            }
                        }
                    }
                },
                "by_rule": {
                    "terms": {
                        "field": "rule.id",
                        "size": 10
                    },
                    "aggs": {
                        "rule_description": {
                            "terms": {
                                "field": "rule.description",
                                "size": 1
                            }
                        }
                    }
                },
                "by_detector": {
                    "terms": {
                        "field": "rule.groups",
                        "size": 10
                    }
                }
            }
        }
        
        try:
            trends_result = app_state.es_client.search(index=DEFAULT_INDEX, body=trends_query)
        except Exception as e:
            logger.error(f"Error querying Elasticsearch for agent stats: {str(e)}")
            return jsonify({"success": False, "error": str(e)}), 500
            
        # Process the trends data
        time_buckets = trends_result["aggregations"]["alerts_over_time"]["buckets"]
        trends_data = []
        
        for bucket in time_buckets:
            timestamp = bucket["key_as_string"]
            total_count = bucket["doc_count"]
            
            # Get counts by level
            level_buckets = bucket["by_level"]["buckets"]
            level_counts = {str(level_bucket["key"]): level_bucket["doc_count"] for level_bucket in level_buckets}
            
            # Add to trends data
            trends_data.append({
                "timestamp": timestamp,
                "total": total_count,
                "byLevel": level_counts
            })
            
        # Process top rules
        rule_buckets = trends_result["aggregations"]["by_rule"]["buckets"]
        top_rules = []
        
        for bucket in rule_buckets:
            rule_id = bucket["key"]
            count = bucket["doc_count"]
            
            # Get rule description
            desc_buckets = bucket["rule_description"]["buckets"]
            description = desc_buckets[0]["key"] if desc_buckets else "Unknown"
            
            top_rules.append({
                "id": rule_id,
                "description": description,
                "count": count
            })
            
        # Process by detector/rule group
        detector_buckets = trends_result["aggregations"]["by_detector"]["buckets"]
        detector_stats = {bucket["key"]: bucket["doc_count"] for bucket in detector_buckets}
        
        # Build the stats response
        stats = {
            "trends": trends_data,
            "topRules": top_rules,
            "byDetector": detector_stats
        }
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error in get_agent_stats: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@agents_bp.route('/<agent_id>/start', methods=['POST'])
def start_agent_monitoring(agent_id):
    """
    Start monitoring for a specific agent.
    
    Args:
        agent_id: Agent ID
        
    Returns:
        JSON response with success status
    """
    try:
        # Check if already monitoring this agent
        if app_state.monitoring_active and app_state.security_monitor and app_state.security_monitor.agent_id == agent_id:
            return jsonify({"success": True, "message": "Already monitoring this agent"})
            
        # If monitoring a different agent, stop current monitoring
        if app_state.monitoring_active:
            app_state.monitoring_active = False
            if app_state.monitor_thread and app_state.monitor_thread.is_alive():
                app_state.monitor_thread.join(timeout=2.0)
                
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
        
        # Override the agent_id with our parameter
        config_params["agent_id"] = agent_id
        
        # Create SecurityMonitor instance
        from app.api.routes import monitoring_loop  # Import here to avoid circular imports
        
        app_state.security_monitor = SecurityMonitor(
            es_client=app_state.es_client,
            index=config_params.get("index", DEFAULT_INDEX),
            interval=int(config_params.get("interval", DEFAULT_INTERVAL)),
            agent_id=agent_id,
            start_time=start_time if start_time else datetime.now(tz=TZ) - timedelta(seconds=60),
            window_size=window_size
        )
        
        # Register event handlers
        app_state.security_monitor.register_event_callback('alert', app_state.handle_alert)
        app_state.security_monitor.register_event_callback('stats', app_state.handle_stats)
        app_state.security_monitor.register_event_callback('raw_alerts', app_state.handle_raw_alerts)
        
        # Start monitoring thread
        app_state.monitoring_active = True
        app_state.monitor_thread = __import__('threading').Thread(target=monitoring_loop)
        app_state.monitor_thread.daemon = True
        app_state.monitor_thread.start()
        
        logger.info(f"Monitoring started for agent {agent_id}")
        return jsonify({"success": True})
        
    except Exception as e:
        logger.error(f"Error starting agent monitoring: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@agents_bp.route('/<agent_id>/stop', methods=['POST'])
def stop_agent_monitoring(agent_id):
    """
    Stop monitoring for a specific agent.
    
    Args:
        agent_id: Agent ID
        
    Returns:
        JSON response with success status
    """
    try:
        # Check if monitoring this agent
        if not app_state.monitoring_active or not app_state.security_monitor or app_state.security_monitor.agent_id != agent_id:
            return jsonify({"success": True, "message": "Not monitoring this agent"})
            
        # Stop monitoring
        app_state.monitoring_active = False
        
        # Wait for thread to terminate (with timeout)
        if app_state.monitor_thread and app_state.monitor_thread.is_alive():
            app_state.monitor_thread.join(timeout=2.0)
        
        logger.info(f"Monitoring stopped for agent {agent_id}")
        return jsonify({"success": True})
        
    except Exception as e:
        logger.error(f"Error stopping agent monitoring: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500