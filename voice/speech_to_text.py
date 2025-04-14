import whisper
import logging
import tempfile
import os
import torch
from typing import Optional

class SpeechToText:
    def __init__(self, model_name: str = "base"):
        """Initialize the speech-to-text model.
        
        Args:
            model_name (str): Whisper model name (tiny, base, small, medium, large)
        """
        self.logger = logging.getLogger(__name__)
        
        # Check if CUDA is available and use GPU if possible
        device = "cuda" if torch.cuda.is_available() else "cpu"
        self.logger.info(f"Using device: {device}")
        
        # Load model with device specification
        self.model = whisper.load_model(model_name, device=device)
        
        # Use system temp directory
        self.temp_dir = os.path.normpath(tempfile.gettempdir())
        self.logger.info(f"Using system temp directory: {self.temp_dir}")
        
        # Verify temp directory is writable
        test_file = os.path.join(self.temp_dir, 'test.txt')
        try:
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            self.logger.info("Temp directory is writable")
        except Exception as e:
            self.logger.error(f"Error: Temp directory is not writable: {e}")
            raise

    def transcribe(self, audio_file_path: str) -> str:
        """
        Transcribe audio file to text using Whisper.
        
        Args:
            audio_file_path (str): Path to the audio file
            
        Returns:
            str: Transcribed text
        """
        try:
            # Check if file exists
            if not os.path.exists(audio_file_path):
                raise FileNotFoundError(f"Audio file not found: {audio_file_path}")

            # Use GPU if available
            with torch.cuda.device(0) if torch.cuda.is_available() else torch.device('cpu'):
                result = self.model.transcribe(audio_file_path)
                if not result or "text" not in result:
                    raise ValueError("Whisper returned empty result")
                
                transcribed_text = result["text"].strip()
                self.logger.info(f"Transcribed text: '{transcribed_text}'")
                return transcribed_text

        except Exception as e:
            self.logger.error(f"Error in speech-to-text: {e}")
            raise

    def transcribe_stream(self, audio_stream) -> str:
        """
        Transcribe audio stream to text.
        
        Args:
            audio_stream: Audio stream data
            
        Returns:
            str: Transcribed text
        """
        try:
            # Save stream to temporary file
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as temp_file:
                for chunk in audio_stream:
                    temp_file.write(chunk)
                temp_path = temp_file.name

            # Transcribe the temporary file
            transcribed_text = self.transcribe(temp_path)

            # Clean up temporary file
            os.unlink(temp_path)

            return transcribed_text

        except Exception as e:
            self.logger.error(f"Error in stream transcription: {e}")
            raise 