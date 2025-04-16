# VoiceSec - AI Voice-Controlled Vulnerability Scanner

VoiceSec is an AI-powered voice-controlled vulnerability scanner that allows you to perform security scans using natural language voice commands.

## Features

- 🎤 Voice command recognition using Whisper
- 🧠 Natural language processing with Ollama
- 🔍 Vulnerability scanning capabilities
- 🎙️ Voice feedback using text-to-speech
- 🖥️ Web interface for easy interaction

## Prerequisites

- Python 3.8+
- Ollama installed and running locally
- Basic security tools (nmap, trivy, etc.)

## Installation

1. Clone this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Start Ollama (if not already running):
   ```bash
   ollama serve
   ```

## Usage

1. Start the server:
   ```bash
   python main.py
   ```
2. Open your web browser to `http://localhost:8000`
3. Click the microphone button and speak your command
4. Wait for the scan results and voice feedback

## Example Commands

- "Scan IP 192.168.1.10 for open ports"
- "Check if Nginx is vulnerable"
- "List all outdated packages"
- "Run a CVE scan on my web server"

## Project Structure

```
voicesec/
├── main.py              # Main application entry point
├── voice/               # Voice processing module
│   ├── __init__.py
│   ├── speech_to_text.py
│   └── text_to_speech.py
├── scanner/            # Vulnerability scanning module
│   ├── __init__.py
│   ├── nmap_scanner.py
│   └── trivy_scanner.py
├── nlp/                # Natural language processing module
│   ├── __init__.py
│   └── intent_parser.py
└── web/                # Web interface
    ├── __init__.py
    ├── static/
    └── templates/
```

## License

MIT License 