from fastapi import FastAPI, UploadFile, File, HTTPException, Request, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import StreamingResponse, HTMLResponse, JSONResponse
from starlette.websockets import WebSocketDisconnect
import uvicorn
import logging
import json
from typing import AsyncGenerator, Dict, Any
import io
import tempfile
import os
import subprocess
import torch
import whisper
from gtts import gTTS
import requests
import asyncio
from scanners.nmap_scanner import NmapScanner
from nlp.intent_parser import IntentParser
from tts.text_to_speech import TextToSpeech
import websockets
import base64
import ollama
import shutil
import numpy as np
from scipy.io import wavfile
from pydantic import BaseModel, Field
from pathlib import Path
from typing import Optional, Union
import uuid
import re

# Configure logging first
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI()

# Mount static files
app.mount("/static", StaticFiles(directory="web/static"), name="static")

# Initialize templates
templates = Jinja2Templates(directory="web/templates")

# Initialize components
nmap_scanner = NmapScanner()
intent_parser = IntentParser()

# Initialize Whisper model
device = "cuda" if torch.cuda.is_available() else "cpu"
logger.info(f"Using device: {device}")
model = whisper.load_model("base", device=device)

# Create temp directory
temp_dir = tempfile.mkdtemp()
logger.info(f"Using system temp directory: {temp_dir}")
if os.access(temp_dir, os.W_OK):
    logger.info("Temp directory is writable")
else:
    logger.error("Temp directory is not writable")
    raise RuntimeError("Cannot write to temp directory")

# Initialize components
stt_model = whisper.load_model("base", device=device)
tts = TextToSpeech()

class CommandResponse(BaseModel):
    status: str
    text: Optional[str] = None
    command: Optional[str] = None
    target: Optional[str] = None
    scan_type: Optional[str] = None
    open_ports: Optional[list] = None
    vulnerabilities: Optional[list] = None
    security_health: Optional[dict] = None
    voice_response: Optional[bytes] = Field(default=None, exclude=True)
    initial_response: Optional[bytes] = Field(default=None, exclude=True)
    confirmation_response: Optional[bytes] = Field(default=None, exclude=True)
    progress_response: Optional[bytes] = Field(default=None, exclude=True)
    completion_response: Optional[bytes] = Field(default=None, exclude=True)
    interpretation: Optional[str] = None
    message: Optional[str] = None

    class Config:
        arbitrary_types_allowed = True

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/tts")
async def text_to_speech(request: Request):
    try:
        data = await request.json()
        text = data.get("text", "")
        
        if not text:
            return JSONResponse(
                status_code=400,
                content={"error": "No text provided"}
            )
        
        # Generate speech
        tts = gTTS(text=text, lang='en')
        voice_response = io.BytesIO()
        tts.write_to_fp(voice_response)
        voice_response.seek(0)
        
        # Return audio data
        return StreamingResponse(
            voice_response,
            media_type="audio/mpeg"
        )
        
    except Exception as e:
        logger.error(f"Error in TTS endpoint: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": str(e)}
        )

def convert_webm_to_wav(webm_path: str) -> str:
    """Convert WebM audio to WAV format using ffmpeg."""
    wav_path = webm_path.replace('.webm', '.wav')
    try:
        subprocess.run([
            'ffmpeg', '-i', webm_path,
            '-acodec', 'pcm_s16le',
            '-ar', '16000',
            '-ac', '1',
            wav_path
        ], check=True)
        return wav_path
    except subprocess.CalledProcessError as e:
        logger.error(f"Error converting WebM to WAV: {e}")
        raise HTTPException(status_code=500, detail="Failed to convert audio format")

async def get_ollama_response(prompt: str, context: str = "") -> str:
    """Get a dynamic response from Ollama with context."""
    try:
        # Add context to make responses more conversational
        full_prompt = f"""You are a friendly security scanning assistant. 
        {context}
        {prompt}
        Please respond in a conversational, helpful tone. Keep responses concise and clear."""
        
        logger.info(f"Sending prompt to Ollama: {full_prompt}")
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama2",
                "prompt": full_prompt,
                "stream": False,
                "options": {
                    "temperature": 0.7,
                    "top_p": 0.9,
                    "max_tokens": 150
                }
            }
        )
        response.raise_for_status()
        ollama_response = response.json()["response"].strip()
        logger.info(f"Received Ollama response: {ollama_response}")
        return ollama_response
    except Exception as e:
        logger.error(f"Error getting Ollama response: {str(e)}")
        return "I'm having trouble generating a response right now. Let me try that again."

async def generate_voice_response(text: str) -> bytes:
    """Generate voice response using gTTS."""
    try:
        # Create a temporary file to store the audio
        temp_file = os.path.join(temp_dir, f"voice_{uuid.uuid4()}.mp3")
        
        # Generate speech with gTTS
        tts = gTTS(text=text, lang='en', slow=False)
        tts.save(temp_file)
        
        # Read the generated audio file
        with open(temp_file, "rb") as f:
            audio_data = f.read()
        
        # Clean up the temporary file
        try:
            os.unlink(temp_file)
        except Exception as e:
            logger.error(f"Error cleaning up temporary file: {str(e)}")
        
        return audio_data
    except Exception as e:
        logger.error(f"Error generating voice response: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate voice response: {str(e)}"
        )

async def interpret_scan_results(scan_result: dict) -> str:
    """Interpret scan results using Ollama."""
    try:
        # Format scan results for interpretation
        open_ports = len(scan_result.get('open_ports', []))
        vulnerabilities = len(scan_result.get('vulnerabilities', []))
        health_status = scan_result.get('security_health', {}).get('status', 'unknown')
        
        # Create detailed context for Ollama
        context = f"""I have completed a security scan with the following results:
        - Found {open_ports} open ports
        - Found {vulnerabilities} potential vulnerabilities
        - Security health status: {health_status}
        
        Please provide a detailed analysis of these findings in a conversational tone, explaining:
        1. The significance of the open ports
        2. Any potential security risks
        3. Recommendations for improving security
        """
        
        logger.info("Sending scan results to Ollama for interpretation")
        interpretation = await get_ollama_response(
            "Analyze these security scan results and provide recommendations.",
            context
        )
        logger.info(f"Received scan interpretation: {interpretation}")
        return interpretation
    except Exception as e:
        logger.error(f"Error interpreting scan results: {str(e)}")
        return "I had trouble analyzing the scan results. Let me try again."

async def process_command(audio_data: bytes) -> AsyncGenerator[Dict[str, Any], None]:
    """Process voice command and yield results with voice response."""
    try:
        # Convert audio bytes to numpy array
        import numpy as np
        from scipy.io import wavfile
        import io
        import torch
        
        # Create a temporary WAV file in memory
        audio_file = io.BytesIO(audio_data)
        
        # Read the audio data
        try:
            sample_rate, audio_array = wavfile.read(audio_file)
        except ValueError:
            # If not WAV, try to convert from WebM
            import subprocess
            import tempfile
            
            # Generate unique filenames
            unique_id = str(uuid.uuid4())
            webm_path = os.path.join(temp_dir, f"audio_{unique_id}.webm")
            wav_path = os.path.join(temp_dir, f"audio_{unique_id}.wav")
            
            try:
                # Write WebM file
                with open(webm_path, "wb") as webm_file:
                    webm_file.write(audio_data)
                
                # Convert WebM to WAV using ffmpeg
                subprocess.run([
                    'ffmpeg', '-y',  # Add -y to force overwrite
                    '-i', webm_path,
                    '-acodec', 'pcm_s16le',
                    '-ar', '16000',
                    '-ac', '1',
                    wav_path
                ], check=True)
                
                # Read the converted WAV file
                sample_rate, audio_array = wavfile.read(wav_path)
                
            finally:
                # Clean up temporary files
                try:
                    if os.path.exists(webm_path):
                        os.unlink(webm_path)
                    if os.path.exists(wav_path):
                        os.unlink(wav_path)
                except Exception as e:
                    logger.error(f"Error cleaning up temporary files: {str(e)}")
        
        # Convert audio array to float32 and normalize
        audio_array = audio_array.astype(np.float32) / 32768.0  # Convert to float32 and normalize
        
        # Convert to torch tensor
        audio_tensor = torch.from_numpy(audio_array)
        
        # Transcribe audio
        result = stt_model.transcribe(audio_tensor)
        text = result["text"].strip() if result and "text" in result else None
        
        if not text:
            yield {
                "status": "error",
                "message": "Could not transcribe audio",
                "voice_response": await generate_voice_response("I'm sorry, I couldn't understand your command. Please try again.")
            }
            return

        # Parse intent
        intent = intent_parser.parse_intent(text)
        if not intent or intent.get("status") != "success":
            yield {
                "status": "error",
                "message": "Could not understand command",
                "voice_response": await generate_voice_response("I'm sorry, I couldn't understand what you want me to do. Please try again.")
            }
            return

        # Extract command details
        command = intent.get("command", "")
        target = intent.get("target", "")
        scan_type = intent.get("scan_type", "port-scan")
        mode = intent.get("mode", "port-scan")

        # Validate scan type
        valid_scan_types = ["port-scan", "vulnerability", "service"]
        if scan_type not in valid_scan_types:
            yield {
                "status": "error",
                "message": f"Unsupported scan type: {scan_type}. Please use one of: {', '.join(valid_scan_types)}",
                "voice_response": await generate_voice_response(
                    f"I'm sorry, I don't support {scan_type} scans. "
                    f"I can perform port scans, vulnerability scans, or service scans. "
                    "Please try again with one of these scan types."
                )
            }
            return

        # Generate initial voice response
        initial_response = await generate_voice_response(f"I'll help you {command}.")

        # Send initial response
        yield {
            "status": "processing",
            "text": text,
            "initial_response": initial_response,
            "progress": 0,
            "progress_message": "Initializing scan..."
        }

        # Process scan command
        if "scan" in command.lower():
            # Run scan with progress updates
            async for progress_update in run_scan_with_progress(target, scan_type):
                yield progress_update

            # Get scan results
            scanner = NmapScanner()
            try:
                scan_results = scanner.scan(target, scan_type)
            except Exception as e:
                error_message = f"Scan failed: {str(e)}"
                yield {
                    "status": "error",
                    "message": error_message,
                    "voice_response": await generate_voice_response(
                        f"I'm sorry, the {scan_type} scan failed. {str(e)} "
                        "Please try again with a different scan type or target."
                    )
                }
                return
            
            # Get AI interpretation
            interpretation = await get_ollama_response(
                f"You are a friendly security scanning assistant. "
                f"I have completed a {scan_type} scan on {target} with the following results:\n"
                f"Open ports: {len(scan_results.get('open_ports', []))}\n"
                f"Vulnerabilities found: {len(scan_results.get('vulnerabilities', []))}\n"
                f"Security health status: {scan_results.get('security_health', {}).get('status', 'unknown')}\n\n"
                f"Please provide a brief, clear interpretation of these findings."
            )

            # Generate final voice response
            final_response = await generate_voice_response(interpretation)

            # Send final results
            yield {
                "status": "success",
                "text": text,
                "results": scan_results,
                "interpretation": interpretation,
                "voice_response": final_response
            }

        else:
            yield {
                "status": "error",
                "message": "Unsupported command",
                "voice_response": await generate_voice_response("I'm sorry, I don't support that command yet.")
            }

    except Exception as e:
        logger.error(f"Error processing command: {str(e)}")
        yield {
            "status": "error",
            "message": str(e),
            "voice_response": await generate_voice_response("I'm sorry, something went wrong. Please try again.")
        }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time communication."""
    await websocket.accept()
    print("WebSocket connection established")
    
    try:
        while True:
            # Receive audio data
            data = await websocket.receive_bytes()
            print("Received audio data")
            
            # Process command and stream results
            async for result in process_command(data):
                # Send JSON response first
                json_response = {
                    "status": result.get("status"),
                    "text": result.get("text"),
                    "results": result.get("results"),
                    "message": result.get("message"),
                    "interpretation": result.get("interpretation"),
                    "progress": result.get("progress", 0),
                    "progress_message": result.get("progress_message", "")
                }
                await websocket.send_json(json_response)
                
                # Send voice responses in sequence
                if result.get("initial_response"):
                    await websocket.send_bytes(result["initial_response"])
                    await asyncio.sleep(2)  # Wait for audio to play
                
                if result.get("confirmation_response"):
                    await websocket.send_bytes(result["confirmation_response"])
                    await asyncio.sleep(2)
                
                if result.get("voice_response"):
                    await websocket.send_bytes(result["voice_response"])
                    await asyncio.sleep(2)
    
    except WebSocketDisconnect:
        print("WebSocket connection closed")
    except Exception as e:
        print(f"WebSocket error: {str(e)}")
        await websocket.close()

async def run_scan_with_progress(target: str, scan_type: str) -> AsyncGenerator[Dict[str, Any], None]:
    """Run Nmap scan with progress updates."""
    try:
        scanner = NmapScanner()
        
        # Create temporary XML output file
        import tempfile
        import os
        import uuid
        import subprocess
        import time
        
        unique_id = str(uuid.uuid4())
        xml_output = os.path.join(tempfile.gettempdir(), f"nmap_{unique_id}.xml")
        
        try:
            # Build Nmap command
            nmap_cmd = f"nmap {scanner.scan_modes[scan_type]} -oX {xml_output} {target}"
            print(f"\nStarting Nmap scan with command: {nmap_cmd}\n")
            
            # Start Nmap process
            process = subprocess.Popen(
                nmap_cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            start_time = time.time()
            ports_found = 0
            services_identified = 0
            
            # Monitor process output
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                
                if output:
                    # Print Nmap output to terminal
                    print(output.strip())
                    
                    # Parse progress information
                    if "Discovered open port" in output:
                        # Extract port number from the output
                        port_match = re.search(r'port (\d+)/', output)
                        if port_match:
                            port = port_match.group(1)
                            ports_found += 1
                            progress = min(50 + (ports_found * 5), 90)  # Cap at 90%
                            yield {
                                "status": "processing",
                                "progress": progress,
                                "progress_message": f"Found {ports_found} open ports...",
                                "voice_response": await generate_voice_response(
                                    f"Found port {port} open."
                                )
                            }
                    elif "Service detection performed" in output:
                        # Extract port and service information
                        service_match = re.search(r'port (\d+)/.*?(\w+)', output)
                        if service_match:
                            port = service_match.group(1)
                            service = service_match.group(2)
                            services_identified += 1
                            yield {
                                "status": "processing",
                                "progress": 95,
                                "progress_message": f"Identified service on port {port}...",
                                "voice_response": await generate_voice_response(
                                    f"Identified {service} service on port {port}."
                                )
                            }
            
            # Get final results
            scan_results = scanner.scan(target, scan_type)
            scan_duration = time.time() - start_time
            
            # Generate summary voice response
            summary = (
                f"Scan completed in {int(scan_duration)} seconds. "
                f"Found {len(scan_results.get('open_ports', []))} open ports. "
                f"Identified {sum(1 for port in scan_results.get('open_ports', []) if port.get('service') != 'unknown')} services. "
                f"Security status: {scan_results.get('security_health', {}).get('status', 'unknown')}."
            )
            
            yield {
                "status": "success",
                "results": scan_results,
                "progress": 100,
                "progress_message": "Scan completed",
                "voice_response": await generate_voice_response(summary)
            }
            
        finally:
            # Clean up temporary file
            try:
                if os.path.exists(xml_output):
                    os.unlink(xml_output)
            except Exception as e:
                print(f"Error cleaning up temporary file: {str(e)}")
                
    except Exception as e:
        yield {
            "status": "error",
            "message": str(e),
            "voice_response": await generate_voice_response(f"Scan failed: {str(e)}")
        }

@app.post("/api/process-voice")
async def process_voice(file: UploadFile = File(...)):
    try:
        # Read the audio file
        audio_data = await file.read()
        
        # Process the command
        async for result in process_command(audio_data):
            # Generate voice responses
            if result.status == "success":
                # Generate initial greeting
                initial_text = "Hello! I'm your security scanning assistant. How can I help you today?"
                result.initial_response = await generate_voice_response(initial_text)
                
                # Generate confirmation
                confirmation_text = f"I'll help you perform a {result.scan_type} scan on {result.target}."
                result.confirmation_response = await generate_voice_response(confirmation_text)
                
                # Generate results summary
                open_ports = len(result.open_ports or [])
                vulnerabilities = len(result.vulnerabilities or [])
                health_status = result.security_health.get('status', 'unknown') if result.security_health else 'unknown'
                
                results_text = (
                    f"I found {open_ports} open ports and {vulnerabilities} potential vulnerabilities. "
                    f"The security health status is {health_status}. "
                    "Would you like me to explain any of these findings in more detail?"
                )
                result.voice_response = await generate_voice_response(results_text)
                
            elif result.status == "error":
                # Generate error message
                error_text = f"I encountered an error: {result.message}. Please try again."
                result.voice_response = await generate_voice_response(error_text)
            
            return result
        
    except Exception as e:
        logger.error(f"Error processing voice command: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/play-voice/{filename}")
async def play_voice(filename: str):
    try:
        file_path = os.path.join(temp_dir, filename)
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Voice file not found")
            
        return StreamingResponse(
            open(file_path, "rb"),
            media_type="audio/mpeg",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )
    except Exception as e:
        logger.error(f"Error playing voice file: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True) 