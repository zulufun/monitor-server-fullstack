from typing import Dict, List, Any
import logging

from security.base import BaseDetector, detector_registry
from security.detectors.utils import check_pattern_match, handle_exceptions

logger = logging.getLogger(__name__)

@detector_registry()
class UACBypassDetector(BaseDetector):
    """
    Detector for UAC bypass attempts based on specific patterns and conditions.
    """
    
    def __init__(self):
        super().__init__(
            name="uac_bypass",
            alert_type="UAC Bypass",
            counter_key="bypassuac"
        )
    
    @handle_exceptions(default_return=[])
    def detect(self, records: List[Dict]) -> List[Dict]:
        """
        Filter records for UAC bypass attempts based on specific patterns and conditions.

        Args:
            records: List of event records to check

        Returns:
            List of records matching UAC bypass patterns
        """
        results = []

        for record in records:
            try:
                # Check basic conditions first - using direct access to match original
                if (
                    record["data"]["win"]["system"]["eventID"] == "1"
                    and record["data"]["win"]["eventdata"]["integrityLevel"] == "High"
                ):
                    # Run through each bypass technique
                    if self._check_dism_bypass(record) or \
                       self._check_fodhelper_bypass(record) or \
                       self._check_wusa_bypass(record) or \
                       self._check_cleanmgr_bypass(record) or \
                       self._check_dccw_bypass(record) or \
                       self._check_osk_bypass(record) or \
                       self._check_slui_bypass(record):
                        results.append(record)

            except Exception as e:
                logger.debug(f"Error processing record in UAC bypass detector: {str(e)}")
                continue

        return results
    
    def _check_dism_bypass(self, record: Dict) -> bool:
        """Check for DISM bypass technique"""
        try:
            parent_cmd = record["data"]["win"]["eventdata"]["parentCommandLine"].lower()
            image = record["data"]["win"]["eventdata"]["image"].lower()
            return all(
                check_pattern_match(pattern=x, text=parent_cmd)
                for x in ["c:\\\\windows\\\\system32\\\\dism.exe", ".xml"]
            ) and all(
                check_pattern_match(pattern=x, text=image)
                for x in ["c:\\\\users\\\\", "\\\\dismhost.exe"]
            )
        except Exception:
            return False
    
    def _check_fodhelper_bypass(self, record: Dict) -> bool:
        """Check for Fodhelper bypass technique"""
        try:
            parent_image = record["data"]["win"]["eventdata"]["parentImage"].lower()
            return check_pattern_match(
                pattern="c:\\\\windows\\\\system32\\\\fodhelper.exe",
                text=parent_image,
            )
        except Exception:
            return False
    
    def _check_wusa_bypass(self, record: Dict) -> bool:
        """Check for WUSA bypass technique"""
        try:
            cmd_line = record["data"]["win"]["eventdata"]["commandLine"].lower()
            current_dir = (
                record["data"]["win"]["eventdata"]
                .get("currentDirectory", "")
                .lower()
            )
            parent_image = record["data"]["win"]["eventdata"]["parentImage"].lower()
            return (
                check_pattern_match(
                    pattern="c:\\\\windows\\\\system32\\\\wusa.exe",
                    text=cmd_line,
                )
                and check_pattern_match(pattern="/quiet", text=cmd_line)
                and current_dir == "c:\\\\windows\\\\system32\\\\"
                and check_pattern_match(
                    pattern="c:\\\\windows\\\\explorer.exe", text=parent_image
                )
            )
        except Exception:
            return False
    
    def _check_cleanmgr_bypass(self, record: Dict) -> bool:
        """Check for Cleanmgr bypass technique"""
        try:
            cmd_line = record["data"]["win"]["eventdata"]["commandLine"].lower()
            parent_image = record["data"]["win"]["eventdata"]["parentImage"].lower()
            return check_pattern_match(
                pattern="cleanmgr.exe /autoclean", text=cmd_line
            ) and check_pattern_match(
                pattern="c:\\\\windows\\\\explorer.exe", text=parent_image
            )
        except Exception:
            return False
    
    def _check_dccw_bypass(self, record: Dict) -> bool:
        """Check for DCCW bypass technique"""
        try:
            parent_image = record["data"]["win"]["eventdata"]["parentImage"].lower()
            image = record["data"]["win"]["eventdata"]["image"].lower()
            return check_pattern_match(
                pattern="c:\\\\windows\\\\dccw.exe", text=parent_image
            ) and check_pattern_match(
                pattern="c:\\\\windows\\\\system32\\\\cttune.exe", text=image
            )
        except Exception:
            return False
    
    def _check_osk_bypass(self, record: Dict) -> bool:
        """Check for OSK bypass technique"""
        try:
            image = record["data"]["win"]["eventdata"]["image"].lower()
            return check_pattern_match(
                pattern="c:\\\\program files\\\\windows media player\\\\osk.exe",
                text=image,
            )
        except Exception:
            return False
    
    def _check_slui_bypass(self, record: Dict) -> bool:
        """Check for SLUI bypass technique"""
        try:
            parent_image = record["data"]["win"]["eventdata"]["parentImage"].lower()
            image = record["data"]["win"]["eventdata"]["image"].lower()
            return check_pattern_match(
                "c:\\\\windows\\\\system32\\\\slui.exe", parent_image
            ) and any(
                check_pattern_match(pattern=f"{x}", text=image)
                for x in [
                    "cmd.exe",
                    "powershell.exe",
                    "rundll32.exe",
                    "regsvr32.exe",
                ]
            )
        except Exception:
            return False