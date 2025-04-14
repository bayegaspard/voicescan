import subprocess
import json
from typing import Dict, Optional, List

class NmapScanner:
    def __init__(self):
        """Initialize the Nmap scanner."""
        self.available_modes = {
            "port-scan": "",  # TCP SYN scan
            "vuln-scan": "-sV --script vuln",  # Version detection + vulnerability scripts
            "os-scan": "-O",  # OS detection
            "full-scan": " -sV -O -A"  # Aggressive scan
        }
    
    def scan(self, target: str, mode: str = "port-scan") -> Optional[Dict]:
        """Perform an Nmap scan on the target.
        
        Args:
            target (str): Target IP or hostname
            mode (str): Type of scan to perform
            
        Returns:
            Optional[Dict]: Scan results in JSON format or None if scan fails
        """
        try:
            if mode not in self.available_modes:
                print(f"Invalid scan mode: {mode}")
                return None
            
            # Build the Nmap command
            nmap_args = ["nmap", self.available_modes[mode], "-p-", target]
            
            # Run Nmap and capture output
            result = subprocess.run(
                nmap_args,
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse XML output to JSON
            return self._parse_nmap_xml(result.stdout)
            
        except subprocess.CalledProcessError as e:
            print(f"Nmap scan failed: {e}")
            return None
        except Exception as e:
            print(f"Error during scan: {e}")
            return None
    
    def _parse_nmap_xml(self, xml_output: str) -> Dict:
        """Parse Nmap XML output into a structured format.
        
        Args:
            xml_output (str): Nmap XML output
            
        Returns:
            Dict: Parsed scan results
        """
        # This is a simplified parser. In a real implementation,
        # you would want to use a proper XML parser like xml.etree.ElementTree
        # or a dedicated Nmap XML parser.
        
        # For now, we'll return a basic structure
        return {
            "status": "success",
            "raw_output": xml_output,
            "summary": "Scan completed successfully"
        }
    
    def get_available_modes(self) -> List[str]:
        """Get list of available scan modes.
        
        Returns:
            List[str]: List of available scan modes
        """
        return list(self.available_modes.keys()) 