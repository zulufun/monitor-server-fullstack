import os
from dotenv import load_dotenv
import logging
from elasticsearch import Elasticsearch
from security.elasticsearch_client import get_wazuh_alerts
from security.matching import filter_bypassuac_attempt, filter_malicious_shell_connect, filter_lsass_access_attempt
from datetime import datetime, timedelta, timezone

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ES_Connection_Test")

def test_elasticsearch_connection():
    """
    Test connection to Elasticsearch using credentials from .env file
    """
    # Load environment variables from .env file
    load_dotenv()
    
    # Get credentials from environment variables
    es_host = os.getenv("ES_HOST")
    es_port = os.getenv("ES_PORT")
    es_user = os.getenv('ES_USER')
    es_password = os.getenv('ES_PASSWORD')
    es_use_ssl = os.getenv('ES_USE_SSL', 'true').lower() == 'true'
    
    # Display the configuration (without password)
    logger.info(f"Testing connection to Elasticsearch at {es_host}:{es_port}")
    logger.info(f"Using SSL: {es_use_ssl}")
    logger.info(f"Authentication: {'Enabled' if es_user else 'Disabled'}")
    
    # Validate required environment variables
    required_vars = ["ES_HOST", "ES_PORT"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
        return False
    
    try:
        # Build connection URL
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
        
        # Create Elasticsearch client
        logger.info("Creating Elasticsearch client...")
        es_client = Elasticsearch(connection_url, **conn_args)
        
        # Test connection
        logger.info("Testing connection...")
        if es_client.ping():
            logger.info("✅ Successfully connected to Elasticsearch!")

            alerts = get_wazuh_alerts(
                es_client=es_client,
                start_time=datetime(2025, 4, 1, 9, 40, 0, tzinfo=timezone(timedelta(hours=7))).isoformat()
            )
            filtered_alerts = filter_lsass_access_attempt(alerts)
            print(filtered_alerts)
            
            return True
        else:
            logger.error("❌ Failed to connect to Elasticsearch: ping failed")
            return False
            
    except Exception as e:
        logger.error(f"❌ Error connecting to Elasticsearch: {str(e)}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("  ELASTICSEARCH CONNECTION TEST")
    print("=" * 60)
    
    success = test_elasticsearch_connection()
    
    print("=" * 60)
    if success:
        print("✅ CONNECTION TEST SUCCESSFUL")
    else:
        print("❌ CONNECTION TEST FAILED")
    print("=" * 60)