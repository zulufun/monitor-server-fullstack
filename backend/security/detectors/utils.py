import re
from typing import Dict, List, Any, Callable, Optional
from functools import wraps
import logging

logger = logging.getLogger(__name__)

def handle_exceptions(default_return=None):
    """
    Decorator to handle exceptions in detector functions.
    Returns default_return (usually empty list) when exceptions occur.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Exception in {func.__name__}: {str(e)}")
                return default_return
        return wrapper
    return decorator


def check_pattern_match(text: str, pattern: str) -> bool:
    """
    Check if text matches the given pattern:
    - If pattern contains *, use regex match
    - If pattern doesn't contain *, check if text contains pattern

    Args:
        text (str): Text to check
        pattern (str): Pattern to match against

    Returns:
        bool: True if matches pattern, False otherwise
    """
    try:
        # If no asterisk in pattern, do simple contains check
        if "*" not in pattern:
            return pattern in text

        # If pattern has asterisk, use regex match
        # Convert the pattern to regex by escaping special chars and converting * to .*
        regex_pattern = pattern.replace("\\", "\\\\")  # Escape backslashes first
        for char in [".", "^", "$", "+", "?", "(", ")", "[", "]", "{", "}"]:
            regex_pattern = regex_pattern.replace(char, f"\\{char}")
        regex_pattern = regex_pattern.replace("*", ".*")
        regex_pattern = f"^{regex_pattern}$"
        
        return bool(re.match(regex_pattern, text))
    except re.error as e:
        logger.error(f"Invalid regex pattern: {e}")
        return False
    except Exception as e:
        logger.error(f"Pattern matching error: {e}")
        return False


def safe_get(data: Dict, path: str, default: Any = None) -> Any:
    """
    Safely retrieve a nested value from a dictionary.
    
    Args:
        data: The dictionary to look in
        path: A dot-separated path to the value
        default: Default value if path doesn't exist
        
    Returns:
        The value at the path or default if not found
    """
    if not isinstance(data, dict):
        return default
        
    parts = path.split('.')
    current = data
    
    for part in parts:
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
        
    return current


def matches_all_patterns(text: str, patterns: List[str]) -> bool:
    """Check if text matches all the given patterns"""
    return all(check_pattern_match(text, pattern) for pattern in patterns)


def matches_any_patterns(text: str, patterns: List[str]) -> bool:
    """Check if text matches any of the given patterns"""
    return any(check_pattern_match(text, pattern) for pattern in patterns)