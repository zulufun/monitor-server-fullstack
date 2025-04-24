from typing import Dict, List, Any
import logging

from security.base import BaseDetector, detector_registry
from security.detectors.utils import check_pattern_match, handle_exceptions

logger = logging.getLogger(__name__)

@detector_registry()
class MaliciousShellDetector(BaseDetector):
    """
    Detect malicious PowerShell code attempting to connect outside.
    Correlates records by processId to find:
    1. PowerShell commands with suspicious parameters/methods
    2. Network connection messages from the same process
    """
    
    def __init__(self):
        super().__init__(
            name="malicious_shell",
            alert_type="Malicious PowerShell",
            counter_key="malicious_shell"
        )
        
        # Suspicious PowerShell parameters and methods (using original casing)
        self.suspicious_patterns = [
            "-nop",
            "-w",
            "hidden",
            "FromBase64String".lower(),
            "GzipStream".lower(),
            "MemoryStream".lower(),
        ]
    
    @handle_exceptions(default_return=[])
    def detect(self, records: List[Dict]) -> List[Dict]:
        """
        Detect malicious PowerShell code attempting to connect outside.
        Correlates records by processId to find:
        1. PowerShell commands with suspicious parameters/methods
        2. Network connection messages from the same process

        Args:
            records: List of event records to check

        Returns:
            List of filtered suspicious records
        """
        # Track suspicious processes and their records
        suspicious_processes = {}  # processId -> [records]

        for record in records:
            try:
                event_data = record["data"]["win"]["eventdata"]
                system_data = record["data"]["win"]["system"]
                process_id = event_data.get("processId")

                if not process_id:
                    continue

                # Check for malicious PowerShell commands
                try:
                    cmd_line = event_data["commandLine"].lower()
                    image = event_data["image"].lower()
                    
                    # Check if it's PowerShell with suspicious patterns
                    if check_pattern_match(pattern="powershell.exe", text=image) and any(
                        check_pattern_match(pattern=pattern, text=cmd_line)
                        for pattern in self.suspicious_patterns
                    ):
                        if process_id not in suspicious_processes:
                            suspicious_processes[process_id] = []
                        suspicious_processes[process_id].append(record)
                except Exception:
                    pass

                # Check for network connection messages
                try:
                    if system_data["eventID"] == "3":
                        if process_id not in suspicious_processes:
                            suspicious_processes[process_id] = []
                        suspicious_processes[process_id].append(record)
                except Exception:
                    pass

            except Exception:
                continue

        # Filter processes that have both suspicious PowerShell and network connection
        results = []
        for process_id, proc_records in suspicious_processes.items():
            if len(proc_records) >= 2:  # Must have at least 2 records
                # Check if process has both conditions
                has_powershell = False
                has_network = False

                for record in proc_records:
                    try:
                        # Check PowerShell condition
                        if check_pattern_match(
                            pattern="powershell.exe",
                            text=record["data"]["win"]["eventdata"]["image"].lower(),
                        ):
                            has_powershell = True

                        # Check network condition
                        if check_pattern_match(
                            pattern="network connection detected",
                            text=record["data"]["win"]["system"]["message"].lower(),
                        ):
                            has_network = True
                    except Exception:
                        continue

                # If both conditions are met, add all records for this process
                if has_powershell and has_network:
                    results.extend(proc_records)

        return results