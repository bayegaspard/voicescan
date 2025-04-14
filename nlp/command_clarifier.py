import requests
import json
import logging
import re
from typing import Dict, Optional

class CommandClarifier:
    def __init__(self, ollama_url: str = "http://localhost:11434"):
        self.logger = logging.getLogger(__name__)
        self.ollama_url = ollama_url
        self.model = "llama2"  # or any other model you prefer
        self.conversation_history = []

    def extract_target(self, text: str) -> Optional[str]:
        """Extract target IP or hostname from text."""
        # IP address pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        # Hostname pattern including localhost
        hostname_pattern = r'\b(?:localhost|local\s+host|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+)\b'
        
        # Try to find IP first
        ip_match = re.search(ip_pattern, text)
        if ip_match:
            return ip_match.group(0)
        
        # Then try hostname
        hostname_match = re.search(hostname_pattern, text)
        if hostname_match:
            return hostname_match.group(0)
        
        return None

    def clarify_command(self, text: str) -> Dict:
        """
        Use Ollama to clarify and improve the command.
        
        Args:
            text (str): The original command text
            
        Returns:
            Dict: Clarified command and feedback
        """
        try:
            # Add to conversation history
            self.conversation_history.append({"role": "user", "content": text})
            
            # Extract target if present
            target = self.extract_target(text)
            
            # Prepare the prompt for Ollama
            prompt = f"""
            You are a security scanning assistant. The user provided this command: "{text}"
            
            Previous conversation history:
            {json.dumps(self.conversation_history, indent=2)}
            
            Please:
            1. Identify if this is a valid security scanning command
            2. If a target is specified ({target if target else 'no target found'}), proceed with the scan
            3. If not clear, ask for clarification
            4. Suggest the correct command format if needed
            
            Common commands are:
            - port scan on [target]
            - service scan on [target]
            - vulnerability scan on [target]
            
            Respond in JSON format with:
            {{
                "status": "success" or "clarification_needed",
                "original_command": "original text",
                "suggested_command": "corrected command if possible",
                "feedback": "helpful feedback or clarification question",
                "is_valid": true/false,
                "target": "extracted target if found",
                "scan_type": "port-scan/service/vulnerability if clear",
                "should_proceed": true/false
            }}
            """

            # Call Ollama API
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                }
            )

            if response.status_code != 200:
                raise Exception(f"Ollama API error: {response.status_code}")

            # Parse the response
            result = response.json()
            try:
                # Extract the JSON response from the model's text
                response_text = result.get("response", "")
                start_idx = response_text.find("{")
                end_idx = response_text.rfind("}") + 1
                if start_idx >= 0 and end_idx > start_idx:
                    json_str = response_text[start_idx:end_idx]
                    clarification = json.loads(json_str)
                    
                    # Add assistant's response to conversation history
                    self.conversation_history.append({
                        "role": "assistant",
                        "content": clarification.get("feedback", "")
                    })
                    
                    # If we have a target and should proceed, update status
                    if clarification.get("should_proceed", False) and target:
                        clarification["status"] = "success"
                        clarification["is_valid"] = True
                    
                    return clarification
                else:
                    raise ValueError("No JSON found in response")
            except (json.JSONDecodeError, ValueError) as e:
                self.logger.error(f"Error parsing Ollama response: {e}")
                return {
                    "status": "error",
                    "message": "Failed to parse clarification response",
                    "original_command": text
                }

        except Exception as e:
            self.logger.error(f"Error in command clarification: {e}")
            return {
                "status": "error",
                "message": str(e),
                "original_command": text
            }

    def generate_voice_feedback(self, clarification: Dict) -> str:
        """
        Generate voice feedback based on the clarification results.
        
        Args:
            clarification (Dict): The clarification results
            
        Returns:
            str: Text to be converted to speech
        """
        if clarification.get("status") == "error":
            return "I'm sorry, I encountered an error processing your command."
        
        if clarification.get("should_proceed", False):
            scan_type = clarification.get("scan_type", "scan")
            target = clarification.get("target", "the target")
            return f"Understood. I will perform a {scan_type} on {target}."
        
        if not clarification.get("is_valid", False):
            feedback = clarification.get("feedback", "I'm not sure what you want to scan.")
            return f"{feedback} Please try again with a clearer command."
        
        if clarification.get("status") == "clarification_needed":
            return clarification.get("feedback", "Could you please clarify your command?")
        
        return f"Understood. I will perform a {clarification.get('suggested_command', 'scan')}." 