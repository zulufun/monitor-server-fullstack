from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import os
import logging
from elasticsearch import Elasticsearch
from datetime import timezone
# Create a timezone object for +7
tz = timezone(timedelta(hours=7))

# Configure logging
logger = logging.getLogger(__name__)


def create_es_client() -> Elasticsearch:
    """
    Create and return an Elasticsearch client using credentials from environment variables.

    Returns:
        Elasticsearch: Configured Elasticsearch client

    Raises:
        ConnectionError: If connection to Elasticsearch fails
        ValueError: If required environment variables are missing
    """
    try:
        # Get credentials from environment variables
        es_host = os.getenv("ES_HOST")
        es_port = os.getenv("ES_PORT")
        es_user = os.getenv('ES_USER')
        es_password = os.getenv('ES_PASSWORD')
        es_use_ssl = os.getenv('ES_USE_SSL', 'true').lower() == 'true'

        # Validate required environment variables
        required_vars = ["ES_HOST", "ES_PORT"]
        missing_vars = [var for var in required_vars if not os.getenv(var)]

        if missing_vars:
            raise ValueError(
                f"Missing required environment variables: {', '.join(missing_vars)}"
            )

        # Build connection URL with credentials if provided
        protocol = "https" if es_use_ssl else "http"
        connection_url = f"{protocol}://{es_host}:{es_port}"
        
        # Create connection arguments
        conn_args = {}
        
        # Add authentication if credentials are provided
        if es_user and es_password:
            conn_args["http_auth"] = (es_user, es_password)
            
        # Add SSL verification settings if using SSL
        if es_use_ssl:
            conn_args["verify_certs"] = False
            
        # Create and test Elasticsearch client
        es_client = Elasticsearch(connection_url, **conn_args)

        if es_client.ping():
            logger.info("Successfully connected to Elasticsearch")
            return es_client
        else:
            raise ConnectionError("Failed to connect to Elasticsearch")

    except Exception as e:
        logger.error(f"Error connecting to Elasticsearch: {str(e)}")
        raise


def get_wazuh_alerts(
    es_client: Elasticsearch,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    alert_level: Optional[int] = None,
    size: int = 100,
    scroll: str = "2m",
    additional_filters: Optional[List[Dict]] = None,
    index: str = "wazuh-alerts-*",
) -> List[Dict]:
    """
    Fetch Wazuh alerts from Elasticsearch with pagination support.

    Args:
        es_client: Elasticsearch client instance
        start_time: Start time in ISO format (default: 24 hours ago)
        end_time: End time in ISO format (default: now)
        alert_level: Minimum alert level to filter (optional)
        size: Number of results per page
        scroll: Scroll timeout
        additional_filters: List of additional Elasticsearch query filters
        index: Elasticsearch index to query

    Returns:
        List of Wazuh alerts
    """
    # Set default time range if not provided
    if not start_time:
        start_time = (datetime.now(tz=tz) - timedelta(seconds=30)).isoformat()
    if not end_time:
        end_time = datetime.now(tz=tz).isoformat()
    

    # Base query
    query = {
        "bool": {
            "must": [{"range": {"timestamp": {"gte": start_time, "lte": end_time}}}]
        }
    }

    # Add alert level filter if specified
    if alert_level is not None:
        query["bool"]["must"].append({"range": {"rule.level": {"gte": alert_level}}})

    # Add any additional filters
    if additional_filters:
        for filter_item in additional_filters:
            query["bool"]["must"].append(filter_item)

    try:
        # Initial search
        resp = es_client.search(
            index=index,
            query=query,
            size=size,
            scroll=scroll,
            sort=[{"timestamp": {"order": "desc"}}],
        )
    except Exception as e:
        logger.error(f"Error in initial search: {str(e)}")
        return []

    # Get initial batch of results
    all_hits = resp["hits"]["hits"]
    scroll_id = resp["_scroll_id"]

    # Continue scrolling until no more results
    try:
        while True:
            resp = es_client.scroll(scroll_id=scroll_id, scroll=scroll)
            
            # Break if no more hits
            if not resp["hits"]["hits"]:
                break

            # Add this batch of results
            all_hits.extend(resp["hits"]["hits"])
            scroll_id = resp["_scroll_id"]
    except Exception as e:
        logger.error(f"Error during scroll: {str(e)}")
    finally:
        # Clean up scroll
        try:
            es_client.clear_scroll(scroll_id=scroll_id)
        except Exception as e:
            logger.error(f"Error clearing scroll: {str(e)}")

    # Extract and format the results
    alerts = [hit["_source"] for hit in all_hits]
    return alerts