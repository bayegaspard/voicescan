import json
from typing import Dict, Optional
import re
import logging

class IntentParser:
    def __init__(self):
        """Initialize the intent parser."""
        self.logger = logging.getLogger(__name__)
        
        # Define regex patterns for different scan types
        self.port_scan_patterns = [
            r'scan\s+port\s+(?:on\s+)?([^\s]+)',
            r'take\s+port\s+(?:on\s+)?([^\s]+)',
            r'port\s+(?:on\s+)?([^\s]+)',
            r'both\s+scan\s+(?:on\s+)?([^\s]+)',
            r'full\s+scan\s+(?:on\s+)?([^\s]+)'
        ]
        
        self.vulnerability_scan_patterns = [
            r'vulnerability\s+scan\s+(?:on\s+)?([^\s]+)',
            r'vuln\s+scan\s+(?:on\s+)?([^\s]+)',
            r'check\s+vulnerability\s+(?:on\s+)?([^\s]+)'
        ]
        
        self.service_scan_patterns = [
            r'service\s+scan\s+(?:on\s+)?([^\s]+)',
            r'check\s+services?\s+(?:on\s+)?([^\s]+)',
            r'both\s+scan\s+(?:on\s+)?([^\s]+)',
            r'full\s+scan\s+(?:on\s+)?([^\s]+)'
        ]
        
        # IP address and hostname patterns
        self.ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        self.hostname_pattern = r'\b(?:localhost|local\s+host|[\w-]+(?:\.[\w-]+)*)\b'
    
    def parse_intent(self, text: str) -> dict:
        """
        Parse the intent from the given text and return a structured response.
        
        Args:
            text (str): The text to parse
            
        Returns:
            dict: A dictionary containing the parsed intent with the following keys:
                - status: 'success' or 'error'
                - tool: 'nmap'
                - target: The target IP or hostname
                - mode: The scan mode (port-scan, service, vulnerability)
                - message: Error message if status is 'error'
        """
        try:
            # Clean and normalize the text
            text = text.lower().strip()
            text = text.replace("local host", "localhost")
            
            # Initialize result structure
            result = {
                "status": "error",
                "message": "No target found in command",
                "command": text,
                "target": None,
                "scan_type": None,
                "mode": None
            }
            
            # Find target first
            target = None
            for pattern in [self.ip_pattern, self.hostname_pattern]:
                match = re.search(pattern, text)
                if match:
                    target = match.group(0)
                    break
            
            if not target:
                return result
            
            # Determine scan type
            scan_type = None
            if any(re.search(pattern, text) for pattern in self.port_scan_patterns):
                scan_type = "port-scan"
            elif any(re.search(pattern, text) for pattern in self.vulnerability_scan_patterns):
                scan_type = "vulnerability"
            elif any(re.search(pattern, text) for pattern in self.service_scan_patterns):
                scan_type = "service"
            
            if not scan_type:
                # Default to port scan if no specific type is mentioned
                scan_type = "port-scan"
            
            # Check for both/full scan
            if any(re.search(pattern, text) for pattern in self.port_scan_patterns) and \
               any(re.search(pattern, text) for pattern in self.service_scan_patterns):
                return {
                    "status": "success",
                    "tool": "nmap",
                    "target": target,
                    "mode": "both",
                    "message": f"Performing both port and service scan on {target}"
                }
            
            return {
                "status": "success",
                "command": text,
                "target": target,
                "scan_type": scan_type,
                "mode": scan_type,
                "tool": "nmap"  # Add tool for compatibility
            }
            
        except Exception as e:
            self.logger.error(f"Error parsing intent: {str(e)}")
            return {
                "status": "error",
                "message": f"Error parsing command: {str(e)}",
                "command": text
            } 