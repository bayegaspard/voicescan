import re
from typing import Dict, Any, Optional

class IntentParser:
    """Parse voice commands into structured intents."""
    
    def __init__(self):
        # Define scan types and their variations
        self.scan_types = {
            "port-scan": ["port scan", "port scanning", "scan ports", "check ports"],
            "vulnerability": ["vulnerability scan", "vulnerability scanning", "check vulnerabilities", "scan for vulnerabilities"],
            "service": ["service scan", "service scanning", "check services", "scan services"]
        }
        
        # Define commands and their variations
        self.commands = {
            "scan": ["scan", "perform", "run", "execute", "do", "conduct", "carry out"]
        }
        
        # Compile regex patterns
        self.ip_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        
        self.domain_pattern = re.compile(
            r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
    
    def parse_intent(self, text: str) -> Dict[str, Any]:
        """Parse text into structured intent."""
        try:
            text = text.lower().strip()
            
            # Initialize result
            result = {
                "status": "success",
                "command": None,
                "target": None,
                "scan_type": "port-scan",  # Default scan type
                "mode": "port-scan"  # Default mode
            }
            
            # Find command
            command_found = False
            for cmd, variations in self.commands.items():
                if any(variation in text for variation in variations):
                    result["command"] = cmd
                    command_found = True
                    break
            
            if not command_found:
                return {
                    "status": "error",
                    "message": "No valid command found"
                }
            
            # Find scan type
            scan_type_found = False
            for scan_type, variations in self.scan_types.items():
                if any(variation in text for variation in variations):
                    result["scan_type"] = scan_type
                    result["mode"] = scan_type
                    scan_type_found = True
                    break
            
            # Extract target (IP or domain)
            target = None
            
            # First try to find IP address
            ip_match = self.ip_pattern.search(text)
            if ip_match:
                target = ip_match.group(0)
            
            # If no IP found, try to find domain
            if not target:
                # Split text into words and look for potential domains
                words = text.split()
                for word in words:
                    # Remove common punctuation
                    word = word.strip('.,!?')
                    if self.domain_pattern.match(word):
                        target = word
                        break
            
            if not target:
                return {
                    "status": "error",
                    "message": "No valid target (IP address or domain) found"
                }
            
            result["target"] = target
            
            return result
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Error parsing intent: {str(e)}"
            }
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is a valid IP address or domain name."""
        return bool(self.ip_pattern.match(target) or self.domain_pattern.match(target)) 