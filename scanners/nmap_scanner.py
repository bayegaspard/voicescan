import subprocess
import logging
from typing import Dict, List, Optional, Union, Any
import re
import shutil
import ipaddress

class NmapScanner:
    """Nmap scanner for network security analysis."""
    
    def __init__(self):
        # Define non-privileged scan modes
        self.scan_modes = {
            "port-scan": "-sT -T4 -vvv --max-retries 2 --min-rate 100",
            "vulnerability": "-sV -sT -T4 -vvv --max-retries 2 --min-rate 100 --script vuln",
            "service": "-sV -sT -T4 -vvv --max-retries 2 --min-rate 100"
        }
        
        # Set up logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Check if nmap is installed
        if not shutil.which('nmap'):
            raise RuntimeError("Nmap is not installed. Please install Nmap to use this scanner.")

    def scan(self, target: str, scan_type: str = "basic") -> Dict[str, Any]:
        """Run an Nmap scan on the target."""
        if not self._is_valid_target(target):
            return {
                "status": "error",
                "message": f"Invalid target: {target}",
                "summary": "Please provide a valid IP address or hostname"
            }

        try:
            # Build Nmap command based on scan type
            if scan_type == "port":
                cmd = f"nmap -p- -T4 {target}"
            elif scan_type == "service":
                cmd = f"nmap -sV -T4 {target}"
            elif scan_type == "vulnerability":
                cmd = f"nmap -sV --script vuln -T4 {target}"
            else:  # basic scan
                cmd = f"nmap -T4 {target}"

            self.logger.info(f"Running Nmap command: {cmd}")
            
            # Run scan
            process = subprocess.run(
                cmd.split(),
                capture_output=True,
                text=True,
                check=True
            )
            
            output = process.stdout
            self.logger.info(f"Nmap output: {output}")

            # Parse results
            open_ports = []
            vulnerabilities = []
            
            for line in output.splitlines():
                # Parse open ports
                port_match = re.search(r'(\d+)/tcp\s+open\s+(\S+)', line)
                if port_match:
                    port, service = port_match.groups()
                    open_ports.append({
                        "port": int(port),
                        "service": service
                    })
                
                # Parse vulnerabilities
                vuln_match = re.search(r'\|\s*(VULNERABLE):\s*(.+)', line)
                if vuln_match:
                    _, desc = vuln_match.groups()
                    vulnerabilities.append(desc.strip())

            return {
                "status": "success",
                "target": target,
                "scan_type": scan_type,
                "open_ports": open_ports,
                "vulnerabilities": vulnerabilities,
                "raw_output": output,
                "summary": self._generate_summary(open_ports, vulnerabilities)
            }

        except subprocess.CalledProcessError as e:
            error_msg = f"Nmap scan failed: {e.stderr}"
            self.logger.error(error_msg)
            return {
                "status": "error",
                "message": error_msg,
                "summary": "Scan failed due to an error running Nmap"
            }
        except Exception as e:
            error_msg = f"Unexpected error during scan: {str(e)}"
            self.logger.error(error_msg)
            return {
                "status": "error",
                "message": error_msg,
                "summary": "An unexpected error occurred during the scan"
            }

    def _is_valid_target(self, target: str) -> bool:
        """Validate if target is a valid IP or hostname."""
        # Check if it's a valid IP
        try:
            ip = ipaddress.ip_address(target)
            # Don't allow 0.0.0.0 or similar invalid IPs
            if ip.is_unspecified or ip.is_multicast or ip.is_reserved:
                return False
            return True
        except ValueError:
            # Check if it's a valid hostname
            try:
                return all(
                    part and all(c.isalnum() or c in '-.' for c in part)
                    for part in target.split('.')
                )
            except Exception:
                return False

    def _parse_nmap_output(self, output: str) -> Dict:
        """Parse Nmap output into structured data."""
        results = {
            "open_ports": [],
            "services": [],
            "vulnerabilities": [],
            "security_health": {
                "status": "unknown",
                "recommendations": []
            }
        }
        
        # Parse open ports and services
        for line in output.split('\n'):
            if '/open/' in line.lower():
                port_info = line.split()
                if len(port_info) >= 3:
                    port = port_info[0].split('/')[0]
                    protocol = port_info[0].split('/')[1]
                    service = port_info[2]
                    results["open_ports"].append({
                        "port": port,
                        "protocol": protocol,
                        "service": service
                    })
                    results["services"].append(service)
        
        # Assess security health
        if not results["open_ports"]:
            results["security_health"]["status"] = "secure"
            results["security_health"]["recommendations"].append("No open ports found")
        else:
            results["security_health"]["status"] = "needs_attention"
            results["security_health"]["recommendations"].append(
                f"Found {len(results['open_ports'])} open ports that should be reviewed"
            )
        
        return results
    
    def _generate_summary(self, open_ports: List[Dict], vulnerabilities: List[str]) -> str:
        """Generate a human-readable summary of scan results."""
        summary_parts = []
        
        if open_ports:
            port_summary = f"Found {len(open_ports)} open port(s): "
            port_summary += ", ".join(f"{p['port']}/{p['service']}" for p in open_ports)
            summary_parts.append(port_summary)
        else:
            summary_parts.append("No open ports found")
            
        if vulnerabilities:
            vuln_summary = f"Found {len(vulnerabilities)} vulnerability/ies"
            summary_parts.append(vuln_summary)
        else:
            summary_parts.append("No vulnerabilities detected")
            
        return ". ".join(summary_parts) 