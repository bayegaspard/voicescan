import re
from typing import Dict, Optional

class IntentParser:
    """Parse voice commands into structured intents."""
    
    def __init__(self):
        # Define patterns for different types of targets
        self.patterns = {
            'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            'domain': r'\b(?:https?://)?(?:www\.)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        }
        
        # Define scan types and their variations
        self.scan_types = {
            'port-scan': ['port scan', 'port scanning', 'scan ports', 'check ports', 'perform port scan'],
            'vulnerability': ['vulnerability scan', 'vulnerability scanning', 'scan for vulnerabilities', 
                            'check vulnerabilities', 'perform vulnerability scan'],
            'service': ['service scan', 'service scanning', 'scan services', 'check services', 
                       'perform service scan']
        }
        
        # Common domain name variations
        self.domain_variations = {
            'microsoft': ['microsoft', 'micro soft', 'micro-soft'],
            'google': ['google', 'goo gle', 'goo-gle'],
            'amazon': ['amazon', 'ama zon', 'ama-zon']
        }
    
    def _clean_text(self, text: str) -> str:
        """Clean and normalize text for better parsing."""
        # Convert to lowercase
        text = text.lower()
        
        # Remove extra spaces
        text = ' '.join(text.split())
        
        # Fix common domain name variations
        for correct, variations in self.domain_variations.items():
            for variation in variations:
                if variation in text:
                    text = text.replace(variation, correct)
        
        return text
    
    def _extract_target(self, text: str) -> Optional[str]:
        """Extract target from text."""
        # Clean the text first
        text = self._clean_text(text)
        
        # Try to match IPv4
        ipv4_match = re.search(self.patterns['ipv4'], text)
        if ipv4_match:
            # Validate IPv4
            ip = ipv4_match.group()
            if all(0 <= int(octet) <= 255 for octet in ip.split('.')):
                return ip
        
        # Try to match IPv6
        ipv6_match = re.search(self.patterns['ipv6'], text)
        if ipv6_match:
            return ipv6_match.group()
        
        # Try to match domain
        domain_match = re.search(self.patterns['domain'], text)
        if domain_match:
            domain = domain_match.group()
            # Remove http:// or https:// if present
            domain = re.sub(r'^https?://', '', domain)
            # Remove www. if present
            domain = re.sub(r'^www\.', '', domain)
            return domain
        
        return None
    
    def _extract_scan_type(self, text: str) -> str:
        """Extract scan type from text."""
        text = self._clean_text(text)
        for scan_type, variations in self.scan_types.items():
            if any(variation in text for variation in variations):
                return scan_type
        return 'port-scan'  # Default to port scan
    
    def parse_intent(self, text: str) -> Dict:
        """Parse text into structured intent."""
        if not text:
            return {
                "status": "error",
                "message": "No text provided"
            }
        
        try:
            # Clean and normalize the text
            text = self._clean_text(text)
            
            # Extract target
            target = self._extract_target(text)
            if not target:
                return {
                    "status": "error",
                    "message": "Could not identify target in command"
                }
            
            # Extract scan type
            scan_type = self._extract_scan_type(text)
            
            return {
                "status": "success",
                "target": target,
                "scan_type": scan_type
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": f"Error parsing intent: {str(e)}"
            } 