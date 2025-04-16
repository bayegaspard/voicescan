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
import aiohttp
import asyncio
from scanners.nmap_scanner import NmapScanner
from intent_parser import IntentParser
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
from pydub import AudioSegment
import librosa

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

# Create temp directory
temp_dir = tempfile.mkdtemp()
logger.info(f"Using system temp directory: {temp_dir}")
if os.access(temp_dir, os.W_OK):
    logger.info("Temp directory is writable")
else:
    logger.error("Temp directory is not writable")
    raise RuntimeError("Cannot write to temp directory")

# Initialize Whisper model
device = "cuda" if torch.cuda.is_available() else "cpu"
logger.info(f"Using device: {device}")

# Create a persistent cache directory for the model
model_cache_dir = os.path.join(os.path.expanduser("~"), ".cache", "voicesec", "whisper")
os.makedirs(model_cache_dir, exist_ok=True)
logger.info(f"Using model cache directory: {model_cache_dir}")

# Load Whisper model with weights_only=True
try:
    # Override torch.load to use weights_only=True
    original_torch_load = torch.load
    def safe_torch_load(*args, **kwargs):
        kwargs['weights_only'] = True
        return original_torch_load(*args, **kwargs)
    torch.load = safe_torch_load

    # Load model with caching
    model = whisper.load_model("base", device=device, download_root=model_cache_dir)
    logger.info("Whisper model loaded successfully")
except Exception as e:
    logger.error(f"Error loading Whisper model: {str(e)}")
    raise

# Initialize components
stt_model = model  # Use the same model instance
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

def generate_voice_response(text: str) -> bytes:
    """Generate voice response using gTTS."""
    try:
        # Create a BytesIO object to store the audio
        audio_buffer = io.BytesIO()
        
        # Generate speech with gTTS and write to buffer
        tts = gTTS(text=text, lang='en', slow=False)
        tts.write_to_fp(audio_buffer)
        
        # Get the audio data from the buffer
        audio_buffer.seek(0)
        audio_data = audio_buffer.read()
        
        return audio_data
    except Exception as e:
        logger.error(f"Error generating voice response: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate voice response: {str(e)}"
        )

async def get_ollama_response(prompt: str) -> str:
    """Get a response from Ollama."""
    try:
        # Create a friendly, conversational prompt
        full_prompt = f"""You are a friendly security scanning assistant.
        Please analyze the following information and provide a clear, conversational response:
        
        {prompt}
        
        Keep your response natural and easy to understand, focusing on the most important findings."""
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": "llama2",
                    "prompt": full_prompt,
                    "stream": False
                }
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    return result["response"].strip()
                else:
                    error_msg = await response.text()
                    logger.error(f"Ollama API error: {error_msg}")
                    return "I'm having trouble analyzing the results right now. Let me try again."
    except Exception as e:
        logger.error(f"Error getting Ollama response: {str(e)}")
        return "I'm having trouble generating a response right now. Let me try that again."

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
            "Analyze these security scan results and provide recommendations."
        )
        logger.info(f"Received scan interpretation: {interpretation}")
        return interpretation
    except Exception as e:
        logger.error(f"Error interpreting scan results: {str(e)}")
        return "I had trouble analyzing the scan results. Let me try again."

async def run_scan_with_progress(scanner: NmapScanner, target: str, scan_type: str) -> AsyncGenerator[Dict[str, Any], None]:
    """Run a scan with progress updates."""
    try:
        # Initial progress
        yield {
            "status": "progress",
            "percent": 0,
            "message": f"Initializing {scan_type} scan on {target}..."
        }
        await asyncio.sleep(1)

        # Validate target
        if not scanner._is_valid_target(target):
            yield {
                "status": "error",
                "percent": 100,
                "message": f"Invalid target: {target}",
                "summary": "Please provide a valid IP address or hostname"
            }
            return

        # Run scan in thread pool
        loop = asyncio.get_event_loop()
        
        # Start the actual scan in a separate task
        scan_task = loop.run_in_executor(None, scanner.scan, target, scan_type)
        
        # Progress updates based on scan type
        progress_steps = {
            "port": [
                (20, "Initiating port discovery..."),
                (40, "Scanning TCP ports..."),
                (60, "Analyzing open ports..."),
                (80, "Finalizing port scan results..."),
            ],
            "service": [
                (20, "Starting service detection..."),
                (40, "Probing open ports..."),
                (60, "Identifying services..."),
                (80, "Analyzing service versions..."),
            ],
            "vulnerability": [
                (20, "Starting vulnerability scan..."),
                (40, "Running vulnerability scripts..."),
                (60, "Analyzing potential vulnerabilities..."),
                (80, "Assessing security risks..."),
            ],
            "basic": [
                (20, "Starting basic scan..."),
                (40, "Probing target..."),
                (60, "Gathering basic information..."),
                (80, "Analyzing results..."),
            ]
        }

        # Send progress updates while scan is running
        steps = progress_steps.get(scan_type, progress_steps["basic"])
        for percent, message in steps:
            # Check if scan is complete
            if scan_task.done():
                break
                
            yield {
                "status": "progress",
                "percent": percent,
                "message": message
            }
            await asyncio.sleep(2)  # Longer delay between updates

        # Get scan results
        result = await scan_task
        logger.info(f"Scan completed with result: {result}")

        if result["status"] == "error":
            yield {
                "status": "error",
                "percent": 100,
                "message": result["message"],
                "summary": result.get("summary", "Scan failed")
            }
            return

        # Final success result with detailed information
        final_result = {
            "status": "success",
            "percent": 100,
            "message": "Scan completed successfully",
            "target": target,
            "scan_type": scan_type,
            "open_ports": result["open_ports"],
            "vulnerabilities": result["vulnerabilities"],
            "raw_output": result["raw_output"],
            "summary": result["summary"],
            "security_health": {
                "status": "healthy" if not result["vulnerabilities"] else "at_risk",
                "open_ports_count": len(result["open_ports"]),
                "vulnerabilities_count": len(result["vulnerabilities"])
            }
        }
        
        logger.info(f"Sending final result: {final_result}")
        yield final_result

    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        yield {
            "status": "error",
            "percent": 100,
            "message": f"Unexpected error: {str(e)}",
            "summary": "An unexpected error occurred during the scan"
        }

async def process_command(websocket, audio_data: bytes) -> Dict[str, Any]:
    """Process an audio command and return the response."""
    try:
        # Convert audio and transcribe
        temp_webm = f"/tmp/{uuid.uuid4()}.webm"
        temp_wav = f"/tmp/{uuid.uuid4()}.wav"
        
        try:
            # Save WebM audio
            with open(temp_webm, 'wb') as f:
                f.write(audio_data)
            
            # Convert to WAV using ffmpeg
            subprocess.run(['ffmpeg', '-y', '-i', temp_webm, temp_wav], 
                         stdout=subprocess.PIPE, 
                         stderr=subprocess.PIPE)
            
            # Load and process audio
            audio_array, _ = librosa.load(temp_wav, sr=16000)
            audio_tensor = torch.FloatTensor(audio_array)
            
            # Transcribe
            result = stt_model.transcribe(audio_tensor)
            command = result["text"].strip()
            logger.info(f"Transcribed command: {command}")
            
        finally:
            # Cleanup temp files
            for temp_file in [temp_webm, temp_wav]:
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                except Exception as e:
                    logger.error(f"Error cleaning up {temp_file}: {e}")

        # Parse intent
        intent = intent_parser.parse_intent(command)
        logger.info(f"Parsed intent: {intent}")
        
        if intent["status"] == "error":
            error_response = generate_voice_response(
                "I'm sorry, I couldn't understand that command. Could you please try again?"
            )
            return {
                "status": "error",
                "message": intent["message"],
                "voice_response": error_response
            }

        target = intent["target"]
        scan_type = intent["scan_type"]
        
        # Create scanner instance
        nmap_scanner = NmapScanner()
        
        # Initial voice response with friendly message
        initial_response = generate_voice_response(
            f"I'll help you perform a {scan_type} scan on {target}. This may take a few moments while I analyze the system."
        )
        
        # Send initial response immediately
        await websocket.send_json({
            "type": "audio",
            "data": base64.b64encode(initial_response).decode('utf-8'),
            "response_type": "initial"
        })
        
        # Run scan with progress
        scan_result = None
        async for update in run_scan_with_progress(nmap_scanner, target, scan_type):
            # Send progress update through websocket
            await websocket.send_json(update)
            logger.info(f"Sent progress update: {update}")
            
            # Store final result
            if update["status"] in ["success", "error"]:
                scan_result = update
                logger.info(f"Scan completed with result: {scan_result}")

        if not scan_result or scan_result["status"] == "error":
            error_msg = scan_result.get("message", "Unknown error occurred") if scan_result else "Scan failed"
            error_response = generate_voice_response(
                f"I encountered an error while scanning {target}. {error_msg}"
            )
            return {
                "status": "error",
                "message": error_msg,
                "voice_response": error_response
            }

        # Get Ollama interpretation of results
        interpretation_prompt = f"""
        Analyze these network scan results and provide a clear, concise security assessment:
        Target: {target}
        Scan Type: {scan_type}
        Open Ports: {scan_result['open_ports']}
        Vulnerabilities: {scan_result['vulnerabilities']}
        Raw Output: {scan_result['raw_output']}
        
        Focus on:
        1. Security implications of open ports
        2. Severity of vulnerabilities
        3. Recommended actions
        4. Overall security posture
        
        Provide a natural, conversational response suitable for voice output.
        """
        
        # Get AI interpretation
        interpretation = await get_ollama_response(interpretation_prompt)
        logger.info(f"Generated interpretation: {interpretation}")
        
        # Generate final voice response
        voice_response = generate_voice_response(interpretation)

        # Return complete result with all necessary information
        final_result = {
            "status": "success",
            "message": "Scan completed successfully",
            "voice_response": voice_response,
            "target": target,
            "scan_type": scan_type,
            "open_ports": scan_result["open_ports"],
            "vulnerabilities": scan_result["vulnerabilities"],
            "raw_output": scan_result["raw_output"],
            "interpretation": interpretation,
            "security_health": scan_result.get("security_health", {
                "status": "unknown",
                "open_ports_count": 0,
                "vulnerabilities_count": 0
            })
        }
        
        logger.info(f"Sending final result: {final_result}")
        return final_result

    except Exception as e:
        logger.error(f"Error processing command: {e}")
        error_response = generate_voice_response(
            "I'm sorry, but I encountered an error while processing your command. Please try again."
        )
        return {
            "status": "error",
            "message": f"Error processing command: {str(e)}",
            "voice_response": error_response
        }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    print("WebSocket connection established")
    
    try:
        while True:
            # Receive audio data
            data = await websocket.receive_bytes()
            print("Received audio data")
            
            # Process the command and send responses
            result = await process_command(websocket, data)
            
            try:
                # Send initial voice response if available
                if "initial_response" in result and result["initial_response"]:
                    print("Sending initial voice response")
                    await websocket.send_json({
                        "type": "audio",
                        "data": base64.b64encode(result["initial_response"]).decode('utf-8'),
                        "response_type": "initial"
                    })
                    await asyncio.sleep(2)  # Wait for initial response to play
                
                # Send JSON response with scan results
                json_response = {
                    "status": result.get("status"),
                    "message": result.get("message"),
                    "target": result.get("target"),
                    "scan_type": result.get("scan_type"),
                    "open_ports": result.get("open_ports"),
                    "vulnerabilities": result.get("vulnerabilities"),
                    "raw_output": result.get("raw_output"),
                    "interpretation": result.get("interpretation"),
                    "security_health": result.get("security_health")
                }
                await websocket.send_json(json_response)
                
                # Send final voice response if available
                if "voice_response" in result and result["voice_response"]:
                    print("Sending final voice response")
                    await websocket.send_json({
                        "type": "audio",
                        "data": base64.b64encode(result["voice_response"]).decode('utf-8'),
                        "response_type": "final"
                    })
                    
            except Exception as e:
                print(f"Error sending response: {str(e)}")
                continue
                    
    except WebSocketDisconnect:
        print("WebSocket connection closed")
    except Exception as e:
        print(f"WebSocket error: {str(e)}")
        await websocket.close()

@app.post("/api/process-voice")
async def process_voice(file: UploadFile = File(...)):
    try:
        # Read the audio file
        audio_data = await file.read()
        
        # Process the command
        result = await process_command(None, audio_data)
        
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

# Disable uvicorn reload for production
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False) 