import requests
import json
import logging
import tempfile
import os
from typing import Optional, Generator, AsyncGenerator
import io
import httpx
from gtts import gTTS
from pydub import AudioSegment

class TextToSpeech:
    def __init__(self, ollama_url: str = "http://localhost:11434"):
        self.logger = logging.getLogger(__name__)
        self.ollama_url = ollama_url
        self.model = "llama2"  # or any other model you prefer
        self.temp_dir = tempfile.gettempdir()

    async def generate_speech(self, text: str) -> bytes:
        try:
            # Call Ollama API for text-to-speech
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "http://localhost:11434/api/generate",
                    json={
                        "model": "llama2",
                        "prompt": f"Convert this text to natural speech: {text}",
                        "stream": False
                    }
                )
                
                if response.status_code != 200:
                    self.logger.error(f"Ollama API error: {response.text}")
                    return b""
                
                try:
                    data = response.json()
                    if not data or "response" not in data:
                        self.logger.error("Invalid Ollama response format")
                        return b""
                    
                    # Use the response text for TTS
                    speech_text = data["response"]
                    
                    # Generate audio using gTTS
                    tts = gTTS(text=speech_text, lang='en')
                    
                    # Save to temporary file
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.mp3') as temp_file:
                        tts.save(temp_file.name)
                        
                        # Read the file and return as bytes
                        with open(temp_file.name, 'rb') as f:
                            audio_data = f.read()
                        
                        # Clean up
                        os.unlink(temp_file.name)
                        
                        return audio_data
                        
                except json.JSONDecodeError:
                    self.logger.error("Failed to parse Ollama response as JSON")
                    return b""
                except Exception as e:
                    self.logger.error(f"Error in TTS generation: {str(e)}")
                    return b""
                    
        except Exception as e:
            self.logger.error(f"Error in TTS endpoint: {str(e)}")
            return b""

    async def stream_speech(self, text: str) -> AsyncGenerator[bytes, None]:
        """
        Stream speech generation in chunks.
        
        Args:
            text (str): The text to convert to speech
            
        Yields:
            bytes: Chunks of audio data
        """
        try:
            # Generate the complete speech
            audio_data = await self.generate_speech(text)
            if audio_data:
                # Stream in chunks
                chunk_size = 4096
                for i in range(0, len(audio_data), chunk_size):
                    yield audio_data[i:i + chunk_size]
        except Exception as e:
            self.logger.error(f"Error streaming speech: {e}")
            yield b""

    async def save_speech(self, text: str, output_path: Optional[str] = None) -> Optional[str]:
        """
        Save generated speech to a file.
        
        Args:
            text (str): The text to convert to speech
            output_path (Optional[str]): Path to save the audio file
            
        Returns:
            Optional[str]: Path to the saved audio file or None if failed
        """
        try:
            # Generate speech
            audio_data = await self.generate_speech(text)
            if not audio_data:
                return None

            # Determine output path
            if not output_path:
                output_path = os.path.join(self.temp_dir, f"speech_{os.urandom(8).hex()}.mp3")

            # Save to file
            with open(output_path, "wb") as f:
                f.write(audio_data)

            return output_path
        except Exception as e:
            self.logger.error(f"Error saving speech: {e}")
            return None 