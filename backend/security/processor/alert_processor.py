from typing import Dict, List, Optional, Any, Type
import json
import logging
import importlib
import pkgutil
from pathlib import Path

from security.base import BaseDetector

logger = logging.getLogger(__name__)

class AlertProcessor:
    """
    Flexible alert processing system that manages multiple detection modules.
    Automatically loads and registers detectors from the detectors package.
    """
    
    def __init__(self):
        # Dictionary to store alert counters
        self.alert_counters = {
            "total": 0
        }
        
        # Dictionary of registered detectors: name -> instance
        self.detectors = {}
        
        # Auto-load detectors
        self._load_detectors()
    
    def _load_detectors(self):
        """
        Automatically load and register all detectors in the detectors package.
        """
        try:
            # Import the base security module to access the registry
            import security
            
            # Ensure detector registry exists
            if not hasattr(security, 'DETECTOR_REGISTRY'):
                security.DETECTOR_REGISTRY = []
            
            # Import all modules in the detectors package to trigger registration
            from security import detectors
            detector_path = Path(detectors.__file__).parent
            for _, module_name, _ in pkgutil.iter_modules([str(detector_path)]):
                try:
                    importlib.import_module(f'security.detectors.{module_name}')
                except Exception as e:
                    logger.error(f"Error loading detector module {module_name}: {str(e)}")
            
            # Register all detectors from the registry
            for detector_class in security.DETECTOR_REGISTRY:
                try:
                    detector = detector_class()
                    self.register_detector(detector)
                except Exception as e:
                    logger.error(f"Error instantiating detector {detector_class.__name__}: {str(e)}")
                    
            logger.info(f"Loaded {len(self.detectors)} detector modules")
        
        except Exception as e:
            logger.error(f"Error loading detectors: {str(e)}")
    
    def register_detector(self, detector: BaseDetector) -> None:
        """
        Register a detector instance.
        
        Args:
            detector: BaseDetector instance to register
        """
        detector_info = detector.get_info()
        name = detector_info["name"]
        counter_key = detector_info["counter_key"]
        
        # Register the detector
        self.detectors[name] = detector
        
        # Initialize counter if it doesn't exist
        if counter_key not in self.alert_counters:
            self.alert_counters[counter_key] = 0
            
        logger.info(f"Registered detector: {name} (type: {detector_info['alert_type']})")
    
    def process_alerts(self, alerts: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Process alerts through all registered detectors.
        
        Args:
            alerts: List of alerts to process
            
        Returns:
            Dictionary mapping detector names to their detected alerts
        """
        if not alerts:
            return {}
            
        # Track total number of alerts
        self.alert_counters["total"] += len(alerts)
        
        # Process alerts through each detector
        results = {}
        
        for name, detector in self.detectors.items():
            try:
                # Get detector info
                detector_info = detector.get_info()
                counter_key = detector_info["counter_key"]
                alert_type = detector_info["alert_type"]
                
                # Apply the detector
                filtered_alerts = detector.detect(alerts)
                
                # Store results
                results[name] = filtered_alerts
                
                # Update counter and log results
                if filtered_alerts:
                    self.alert_counters[counter_key] += len(filtered_alerts)
                    logger.warning(f"Detected {len(filtered_alerts)} {alert_type} events!")
                    
                    # Log individual alerts
                    for alert in filtered_alerts:
                        agent_id = alert.get('agent', {}).get('id', 'unknown')
                        description = alert.get('rule', {}).get('description', 'No description')
                        logger.warning(f"{alert_type}: Agent {agent_id} - {description}")
                        
                        # Log the full alert details at info level
                        logger.info(f"Full {alert_type} Alert: {json.dumps(alert, indent=2)}")
            
            except Exception as e:
                logger.error(f"Error in detector '{name}': {str(e)}")
        
        return results
    
    def get_stats(self) -> Dict[str, int]:
        """
        Get current alert statistics.
        
        Returns:
            Dictionary of counter names to values
        """
        return self.alert_counters.copy()