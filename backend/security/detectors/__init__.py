"""
Detection modules for security threats.
Import detectors here to ensure they are registered properly.
"""

# Import detectors to ensure they are registered through the decorator
from security.detectors.uac_bypass import UACBypassDetector
from security.detectors.malicious_shell import MaliciousShellDetector
from security.detectors.credential_access import CredentialAccessDetector

# Add any additional detectors here

__all__ = [
    'UACBypassDetector',
    'MaliciousShellDetector',
    'CredentialAccessDetector',
]