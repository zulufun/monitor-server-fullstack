from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any


class BaseDetector(ABC):
    """
    Base class for all security detectors.
    
    New detection modules should inherit from this class and implement
    the required methods.
    """
    
    def __init__(self, name: str, alert_type: str, counter_key: str):
        """
        Initialize a detector with its basic information.
        
        Args:
            name: Unique identifier for this detector
            alert_type: Human-readable alert type (for UI/logging)
            counter_key: Key to use for counter statistics
        """
        self.name = name
        self.alert_type = alert_type
        self.counter_key = counter_key
        
    @abstractmethod
    def detect(self, records: List[Dict]) -> List[Dict]:
        """
        Process records and detect security threats.
        
        Args:
            records: List of event records to analyze
            
        Returns:
            List of records that match detection criteria
        """
        pass
    
    def get_info(self) -> Dict[str, str]:
        """
        Get basic information about this detector.
        
        Returns:
            Dictionary with detector metadata
        """
        return {
            "name": self.name,
            "alert_type": self.alert_type,
            "counter_key": self.counter_key
        }
    
    def should_register(self) -> bool:
        """
        Determine if this detector should be registered.
        Can be overridden to conditionally enable/disable detectors.
        
        Returns:
            True if detector should be registered, False otherwise
        """
        return True


def detector_registry():
    """
    Decorator to register a detector class in the global registry.
    
    Example:
        @detector_registry()
        class MyDetector(BaseDetector):
            # detector implementation
    """
    from importlib import import_module
    
    def decorator(cls):
        if not hasattr(import_module('security'), 'DETECTOR_REGISTRY'):
            import_module('security').DETECTOR_REGISTRY = []
        
        if hasattr(cls, 'should_register') and cls().should_register():
            import_module('security').DETECTOR_REGISTRY.append(cls)
        
        return cls
    
    return decorator