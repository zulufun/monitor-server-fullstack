from typing import Dict, List, Any
import logging

from security.base import BaseDetector, detector_registry
from security.detectors.utils import check_pattern_match, handle_exceptions

logger = logging.getLogger(__name__)

@detector_registry()
class CredentialAccessDetector(BaseDetector):
    """
    Filter records for potential LSASS memory access attempts based on Sysmon Event ID 10.
    Detects attempts to access LSASS memory with specific granted access masks that are 
    commonly associated with credential dumping.
    
    Also detects registry save attempts using reg.exe with high integrity targeting SAM or SYSTEM hives.
    """
    
    def __init__(self):
        super().__init__(
            name="credential_access",
            alert_type="Credential Access",
            counter_key="credential_access"
        )
        
        # Suspicious granted access masks for LSASS
        self.suspicious_access = {'0x1410', '0x1010', '0x1438', '0x143a', '0x1418'}
        
        # Required DLLs in call trace
        self.required_dlls = {
            'c:\\\\windows\\\\system32\\\\ntdll.dll',
            'c:\\\\windows\\\\system32\\\\kernelbase.dll'
        }
        
        # Suspicious registry save targets
        self.suspicious_registry_keys = {'hklm\\\\sam', 'hklm\\\\system', 'hklm\\\\security'}
    
    @handle_exceptions(default_return=[])
    def detect(self, records: List[Dict]) -> List[Dict]:
        """
        Filter records for potential LSASS memory access attempts based on Sysmon Event ID 10.
        Detects attempts to access LSASS memory with specific granted access masks that are 
        commonly associated with credential dumping.
        
        Also detects registry save attempts using reg.exe with high integrity targeting SAM or SYSTEM hives.
        
        Args:
            records: List of event records to check
        Returns:
            List of records matching LSASS access patterns or suspicious registry operations
        """
        results = []
        
        for record in records:
            try:
                # Check for LSASS access attempts (Event ID 10)
                if "data" in record and "win" in record["data"] and "system" in record["data"]["win"] and "eventdata" in record["data"]["win"]:
                    system_data = record["data"]["win"]["system"]
                    event_data = record["data"]["win"]["eventdata"]
                    
                    # Check if it's a Sysmon event
                    if system_data["channel"] == "Microsoft-Windows-Sysmon/Operational":
                        # Check for LSASS access (Event ID 10)
                        if (system_data["eventID"] == "10" and
                            event_data["targetImage"].lower() == "c:\\\\windows\\\\system32\\\\lsass.exe"):
                            
                            # Check granted access mask
                            granted_access = event_data["grantedAccess"].lower()
                            if granted_access not in self.suspicious_access:
                                continue
                                
                            # Check call trace for required DLLs
                            call_trace = event_data.get("callTrace", "").lower()
                            if not all(dll in call_trace for dll in self.required_dlls):
                                continue
                                
                            # If all conditions are met, add to results
                            results.append(record)
                            continue
                            
                        # Check for suspicious registry operations (Event ID 1 - Process Creation)
                        elif system_data["eventID"] == "1":
                            # Check if image is reg.exe
                            if not event_data["image"].lower().endswith("\\reg.exe"):
                                continue
                                
                            # Check integrity level
                            if event_data.get("integrityLevel", "").lower() != "high":
                                continue
                                
                            # Check command line for registry save operations
                            command_line = event_data.get("commandLine", "").lower()
                            if not command_line:
                                continue
                                
                            # Check if command has "save" and one of the suspicious registry keys
                            if "save" in command_line and any(key in command_line for key in self.suspicious_registry_keys):
                                results.append(record)
                                continue
                                
            except Exception as e:
                # Log the error if needed
                continue
                
        return results