import io
import logging
from gtts import gTTS
import tempfile
import os

logger = logging.getLogger(__name__)

class TextToSpeech:
    def __init__(self):
        """Initialize the TextToSpeech class."""
        self.temp_dir = tempfile.mkdtemp()
        logger.info(f"Initialized TextToSpeech with temp directory: {self.temp_dir}")

    def generate_speech(self, text: str) -> bytes:
        """
        Generate speech from text using gTTS.
        
        Args:
            text (str): The text to convert to speech
            
        Returns:
            bytes: The generated audio data
        """
        try:
            # Create gTTS object
            tts = gTTS(text=text, lang='en', slow=False)
            
            # Save to temporary file
            temp_file = os.path.join(self.temp_dir, "temp_speech.mp3")
            tts.save(temp_file)
            
            # Read the file and return bytes
            with open(temp_file, "rb") as f:
                audio_data = f.read()
            
            # Clean up
            os.remove(temp_file)
            
            return audio_data
            
        except Exception as e:
            logger.error(f"Error generating speech: {str(e)}")
            raise RuntimeError(f"Failed to generate speech: {str(e)}")

    def __del__(self):
        """Clean up temporary directory when object is destroyed."""
        try:
            if os.path.exists(self.temp_dir):
                os.rmdir(self.temp_dir)
        except Exception as e:
            logger.warning(f"Error cleaning up temp directory: {str(e)}") 