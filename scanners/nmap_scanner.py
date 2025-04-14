import subprocess
import xml.etree.ElementTree as ET
import tempfile
import os
import shutil
import logging
from typing import Dict, List, Optional, Union
import uuid
import re

class NmapScanner:
    def __init__(self):
        self.scan_modes = {
            "port-scan": " -sV -O -vvv",  # Version detection and OS detection
            "vulnerability": " -sV --script vuln -vvv",  # Vulnerability scan
            "service": " -sV -O -A -vvv"  # Aggressive scan
        }
        
        # Set up logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Check if nmap is installed
        if not shutil.which('nmap'):
            raise RuntimeError("Nmap is not installed. Please install Nmap to use this scanner.")
        
        # Compile regex patterns for validation
        self.ip_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        
        self.domain_pattern = re.compile(
            r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )

    def scan(self, target: str, scan_type: str = "port-scan") -> Dict[str, Union[str, List, Dict]]:
        """
        Run an Nmap scan and return the results.
        
        Args:
            target: The target IP or hostname to scan
            scan_type: Type of scan to perform (port-scan, vulnerability, service, full-scan)
            
        Returns:
            Dictionary containing scan results
        """
        try:
            # Validate target
            if not target:
                raise ValueError("Target is required")
            
            # Validate target format
            if not (self.ip_pattern.match(target) or self.domain_pattern.match(target)):
                raise ValueError(f"Invalid target format: {target}. Must be a valid IP address or domain name.")
            
            # Validate scan type
            if scan_type not in self.scan_modes:
                raise ValueError(f"Unsupported scan type: {scan_type}")
            
            # Create temporary XML output file
            unique_id = str(uuid.uuid4())
            xml_output = os.path.join(tempfile.gettempdir(), f"nmap_{unique_id}.xml")
            
            try:
                # Build Nmap command with proper target handling
                nmap_cmd = f"nmap {self.scan_modes[scan_type]} -oX {xml_output} {target}"
                
                # Run Nmap
                result = subprocess.run(nmap_cmd, shell=True, check=True, capture_output=True, text=True)
                
                # Parse XML output
                tree = ET.parse(xml_output)
                root = tree.getroot()
                
                # Initialize results
                results = {
                    "target": target,
                    "scan_type": scan_type,
                    "open_ports": [],
                    "vulnerabilities": [],
                    "security_health": {
                        "status": "unknown",
                        "recommendations": []
                    }
                }
                
                # Parse host information
                host = root.find(".//host")
                if host is not None:
                    # Get hostname if available
                    hostnames = host.findall(".//hostname")
                    if hostnames:
                        results["hostname"] = hostnames[0].get("name")
                    
                    # Get host status
                    status = host.find(".//status")
                    if status is not None and status.get("state") == "up":
                        # Parse ports
                        for port in host.findall(".//port"):
                            port_id = port.get("portid")
                            state = port.find("state")
                            service = port.find("service")
                            
                            if state is not None and state.get("state") == "open":
                                port_info = {
                                    "port": port_id,
                                    "protocol": port.get("protocol"),
                                    "service": service.get("name") if service is not None else "unknown",
                                    "version": service.get("version") if service is not None else "unknown",
                                    "vulnerabilities": []
                                }
                                
                                # Parse vulnerabilities for this port
                                if scan_type == "vulnerability":
                                    script = port.find(".//script[@id='vulners']")
                                    if script is not None:
                                        for vuln in script.findall(".//elem"):
                                            if vuln.get("key") == "id":
                                                vuln_id = vuln.text
                                                severity = script.find(f".//elem[@key='cvss']")
                                                if severity is not None:
                                                    port_info["vulnerabilities"].append({
                                                        "id": vuln_id,
                                                        "severity": float(severity.text),
                                                        "type": "vulnerability"
                                                    })
                                
                                results["open_ports"].append(port_info)
                
                # Analyze security health
                if results["open_ports"]:
                    # Check for critical vulnerabilities
                    critical_vulns = []
                    for port in results["open_ports"]:
                        for vuln in port.get("vulnerabilities", []):
                            if vuln["severity"] >= 7.0:
                                critical_vulns.append({
                                    "port": port["port"],
                                    "vulnerability": vuln["id"],
                                    "severity": vuln["severity"]
                                })
                    
                    if critical_vulns:
                        results["security_health"]["status"] = "critical"
                        results["security_health"]["recommendations"].append(
                            f"Critical vulnerabilities found: {len(critical_vulns)}. "
                            "Immediate action required."
                        )
                    else:
                        results["security_health"]["status"] = "warning"
                        results["security_health"]["recommendations"].append(
                            "No critical vulnerabilities found, but system should be updated."
                        )
                else:
                    results["security_health"]["status"] = "good"
                    results["security_health"]["recommendations"].append(
                        "No open ports found. System appears secure."
                    )
                
                return results
                
            finally:
                # Clean up temporary file
                try:
                    if os.path.exists(xml_output):
                        os.unlink(xml_output)
                except Exception as e:
                    print(f"Error cleaning up temporary file: {str(e)}")
                    
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Nmap scan failed: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Error running scan: {str(e)}")

    def _parse_xml_output(self, root: ET.Element) -> Dict:
        """
        Parse the Nmap XML output and extract relevant information.
        
        Args:
            root (ET.Element): The root element of the XML tree
            
        Returns:
            Dict: Parsed scan results including ports and services
        """
        ports = []
        
        # Find the host element
        host = root.find(".//host")
        if host is None:
            return {"ports": []}
        
        # Get host address
        address = host.find(".//address")
        host_address = address.get("addr") if address is not None else "unknown"
        
        # Get ports
        for port in root.findall(".//port"):
            port_info = {
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "state": port.find(".//state").get("state") if port.find(".//state") is not None else "unknown",
                "service": {}
            }
            
            # Get service information
            service = port.find(".//service")
            if service is not None:
                port_info["service"] = {
                    "name": service.get("name"),
                    "product": service.get("product"),
                    "version": service.get("version")
                }
            
            ports.append(port_info)
        
        return {
            "host": host_address,
            "ports": ports
        } 