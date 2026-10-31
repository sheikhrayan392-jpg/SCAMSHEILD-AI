"""
ScamShield AI - Audio Transcription & Recorded Call Analysis Module
===================================================================
Provides modular audio validation, acoustic metadata extraction, and a pluggable
transcription interface for analyzing recorded telephone calls and voice notes.

KEY PRINCIPLES:
1. STRICT LOCAL EXECUTION: Never uploads recordings to external cloud APIs or services.
2. RIGOROUS VALIDATION: Enforces a strict 25 MB file size limit and inspects binary audio headers (WAV/MP3).
3. TRANSPARENCY: Clearly identifies whether actual offline STT is active or if manual transcript fallback is in use.
4. DEFENSIVE COMPATIBILITY: Transcripts flow seamlessly into the Guardian Agent (scam risk scoring)
   and Intelligence Agent (unverified entity extraction and gap analysis).
"""

import io
import math
import struct
import wave
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants & Configuration
# ---------------------------------------------------------------------------

MAX_AUDIO_SIZE_BYTES = 25 * 1024 * 1024  # 25 MB hard cap
SUPPORTED_EXTENSIONS = {".wav", ".mp3"}

# Configurable offline Whisper model hierarchy:
# Defaults to 'base' for superior Hindi & English recognition without excessive memory overhead.
# Can be overridden via SCAMSHIELD_WHISPER_MODEL or WHISPER_MODEL environment variables.
DEFAULT_WHISPER_MODEL = os.getenv("SCAMSHIELD_WHISPER_MODEL", os.getenv("WHISPER_MODEL", "small"))
DEFAULT_WHISPER_DEVICE = os.getenv("SCAMSHIELD_WHISPER_DEVICE", "auto")
AVAILABLE_WHISPER_MODELS = ("tiny", "base", "small")

# Cached model singletons to avoid repeated initialization and memory duplication
_LOADED_MODELS: Dict[str, Any] = {}
_RESOLVED_DEVICE_CONFIG: Optional[Tuple[str, str, str]] = None


# ---------------------------------------------------------------------------
# Language & Acoustic Utility Functions
# ---------------------------------------------------------------------------

def normalize_language_code(language: Optional[str]) -> Optional[str]:
    """
    Normalizes language selector input into standard ISO 639-1 language codes.
    Returns:
        - None for automatic language detection
        - 'hi' for Hindi (Devanagari script)
        - 'en' for English (Indian & global accents)
        - sanitized lowercase code for other supported languages
    """
    if not language:
        return None
    clean = str(language).lower().strip()
    if clean in {"auto", "detect", "auto-detect", "auto detect", "none", "all", "unknown", ""}:
        return None
    if clean in {"hi", "hindi", "hin", "हिंदी", "हिन्दी"}:
        return "hi"
    if clean in {"en", "english", "eng", "en-in", "en-us", "en-gb"}:
        return "en"
    return clean


def build_domain_initial_prompt(norm_language: Optional[str]) -> str:
    """
    Constructs a balanced vocabulary prompt to prime Whisper's language model prior.
    Guides correct spelling and script tokenization for conversational phrases as well as
    common authorities and institutions, without forcing synthetic sentences.
    """
    if norm_language == "hi":
        return "नमस्ते, कैसे हो? क्या हाल है? दिल्ली पुलिस, सीबीआई, साइबर सेल, डिजिटल अरेस्ट, वारंट, बैंक, ओटीपी, आधार, कॉलेज, जरूरी सूचना।"
    return "Hello, how are you? Delhi Police Crime Branch, CBI, cyber cell, digital arrest, warrant, bank KYC, OTP, clearance."


def inspect_audio_signal(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Inspects audio signal properties without modifying original audio bytes.
    Analyzes RMS energy level, peak amplitude, and minimum duration thresholds.

    Parameters:
        file_bytes (bytes): Binary audio bytes.
        filename (str): Audio filename for format dispatch.

    Returns:
        dict: Signal metrics including is_near_silent, is_extremely_short, rms, peak, and warning.
    """
    if not file_bytes or not isinstance(file_bytes, (bytes, bytearray)):
        return {
            "is_valid": False,
            "is_near_silent": True,
            "is_extremely_short": True,
            "rms_amplitude": 0.0,
            "peak_amplitude": 0.0,
            "duration_seconds": 0.0,
            "signal_warning": "No audio content provided.",
        }

    lower_name = (filename or "").lower()
    rms = 0.0
    peak = 0.0
    duration_sec = 0.0

    if lower_name.endswith(".wav"):
        try:
            with wave.open(io.BytesIO(file_bytes), "rb") as wav:
                sample_width = wav.getsampwidth()
                rate = wav.getframerate()
                n_frames = wav.getnframes()
                if rate > 0:
                    duration_sec = round(n_frames / float(rate), 2)
                read_count = min(n_frames, 100000)
                if read_count > 0 and sample_width == 2:
                    raw_frames = wav.readframes(read_count)
                    n_samples = len(raw_frames) // 2
                    if n_samples > 0:
                        samples = struct.unpack("<" + "h" * n_samples, raw_frames)
                        sum_sq = sum(s * s for s in samples)
                        rms = math.sqrt(sum_sq / float(n_samples)) / 32768.0
                        peak = max(abs(s) for s in samples) / 32768.0
        except Exception:
            pass
    elif lower_name.endswith(".mp3"):
        try:
            import av
            _ensure_pyav_compatibility()
            with av.open(io.BytesIO(file_bytes), mode="r") as container:
                sample_arrays = []
                if container.duration is not None and container.duration > 0:
                    duration_sec = round(float(container.duration) / 1000000.0, 2)
                for idx, frame in enumerate(container.decode(audio=0)):
                    arr = frame.to_ndarray().flatten()
                    if frame.format.name in {"flt", "fltp"}:
                        sample_arrays.append(arr)
                    elif frame.format.name in {"s16", "s16p"}:
                        sample_arrays.append(arr.astype(float) / 32768.0)
                    if idx >= 30:  # Sample initial frames for fast inspection
                        break
                if sample_arrays:
                    import numpy as np
                    all_s = np.concatenate(sample_arrays)
                    if len(all_s) > 0:
                        rms = float(np.sqrt(np.mean(all_s ** 2)))
                        peak = float(np.max(np.abs(all_s)))
        except Exception:
            pass

    is_near_silent = (peak < 0.015 and rms < 0.002)
    is_extremely_short = (0.0 < duration_sec < 0.5)

    warning = None
    if is_near_silent:
        warning = "Audio appears to be silent or contains only faint background noise."
    elif is_extremely_short:
        warning = f"Audio is extremely short ({duration_sec}s). Speech recognition may be incomplete or unreliable."

    return {
        "is_valid": True,
        "is_near_silent": is_near_silent,
        "is_extremely_short": is_extremely_short,
        "rms_amplitude": round(rms, 4),
        "peak_amplitude": round(peak, 4),
        "duration_seconds": duration_sec,
        "signal_warning": warning,
    }


def resolve_optimal_device(requested_device: str = "auto") -> Tuple[str, str, str]:
    """
    Safely resolves the best compute device and quantization.
    Supports GPU acceleration when available, with resilient fallback to CPU int8.

    Returns:
        tuple: (device_name, compute_type, description_string)
    """
    global _RESOLVED_DEVICE_CONFIG
    req_lower = (requested_device or "auto").lower().strip()
    if req_lower == "cpu":
        return "cpu", "int8", "CPU (int8 quantization)"

    if _RESOLVED_DEVICE_CONFIG is not None and req_lower == "auto":
        return _RESOLVED_DEVICE_CONFIG

    device = "cpu"
    compute_type = "int8"
    description = "CPU (int8 quantization)"

    try:
        import ctranslate2
        if ctranslate2.get_cuda_device_count() > 0:
            # Test actual CUDA runtime viability (ensure cuBLAS libraries are present)
            from faster_whisper import WhisperModel
            import numpy as np
            test_m = WhisperModel("tiny", device="cuda", compute_type="float16")
            test_feat = ctranslate2.StorageView.from_array(np.zeros((1, 80, 100), dtype=np.float32))
            test_m.model.encode(test_feat)
            device = "cuda"
            compute_type = "float16"
            description = "NVIDIA CUDA GPU (float16 acceleration)"
    except Exception as e:
        description = "CPU (int8 quantization) - [CUDA device detected, cuBLAS runtime unavailable]"

    if req_lower == "auto":
        _RESOLVED_DEVICE_CONFIG = (device, compute_type, description)

    return device, compute_type, description


def evaluate_transcript_quality(
    transcript: str,
    overall_confidence: float,
    lang_prob: float,
    detected_language: str,
    requested_language: Optional[str],
    duration_sec: float,
    is_silent: bool = False,
    segments: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Evaluates transcript characteristics and provides transparent quality warnings.
    Avoids blindly certifying transcripts as accurate or fabricating confidence.

    Returns:
        dict: Quality rating ('HIGH', 'MODERATE', 'LOW', 'EMPTY'), warnings list, and reliability flag.
    """
    warnings: List[str] = []
    clean_text = (transcript or "").strip()
    words = clean_text.split()
    word_count = len(words)

    if not clean_text or is_silent:
        return {
            "rating": "EMPTY",
            "score": 0.0,
            "is_reliable": False,
            "word_count": 0,
            "warnings": ["No discernible speech was detected in this recording."],
            "code_switching_detected": False,
        }

    # 1. Check confidence and probability
    if overall_confidence < 0.50:
        warnings.append(
            f"Low acoustic confidence ({round(overall_confidence * 100, 1)}%): Audio may be noisy, distorted, or heavily accented."
        )
    elif overall_confidence < 0.70:
        warnings.append(
            f"Moderate acoustic confidence ({round(overall_confidence * 100, 1)}%): Some words may be misrecognized. Please review the transcript."
        )

    # 2. Check duration vs word count
    if duration_sec > 5.0 and word_count <= 2:
        warnings.append(
            f"Suspiciously brief transcript ({word_count} words in {duration_sec}s): Speech may be faint, muffled, or cut off."
        )

    # 3. Check language consistency & code-switching
    has_devanagari = any("\u0900" <= ch <= "\u097f" for ch in clean_text)
    has_latin = any("a" <= ch.lower() <= "z" for ch in clean_text)
    code_switching = has_devanagari and has_latin

    if code_switching:
        warnings.append(
            "Code-switching detected: Audio contains mixed Hindi and English. Verify proper nouns, department names, and amounts."
        )

    if requested_language == "en" and has_devanagari:
        warnings.append(
            "Language mismatch: English decoding was requested, but Devanagari characters were generated."
        )
    elif requested_language == "hi" and not has_devanagari and word_count > 3:
        warnings.append(
            "Script notice: Hindi decoding was requested, but output was generated primarily in Latin script."
        )
    elif not requested_language and lang_prob < 0.65:
        warnings.append(
            f"Uncertain auto language detection ({detected_language.upper()} at {round(lang_prob * 100, 1)}%): Consider selecting Hindi or English explicitly."
        )

    # 4. Check for repetitive loops (Whisper hallucination symptom)
    if segments and len(segments) >= 3:
        texts = [s.get("text", "").lower().strip() for s in segments if s.get("text")]
        if len(texts) >= 3 and len(set(texts[-3:])) == 1:
            warnings.append(
                "Potential repetitive hallucination detected: Identical text was generated across multiple audio segments."
            )

    # Determine overall rating
    if overall_confidence >= 0.75 and not warnings:
        rating = "HIGH"
        is_reliable = True
    elif overall_confidence >= 0.55 and len(warnings) <= 2:
        rating = "MODERATE"
        is_reliable = True
    else:
        rating = "LOW"
        is_reliable = False

    return {
        "rating": rating,
        "score": round(overall_confidence, 3),
        "is_reliable": is_reliable,
        "word_count": word_count,
        "warnings": warnings,
        "code_switching_detected": code_switching,
    }



# ---------------------------------------------------------------------------
# 1. Audio Validation & Format Verification
# ---------------------------------------------------------------------------

def validate_audio_file(
    file_bytes: Any,
    filename: str,
    max_size_mb: float = 25.0,
) -> Dict[str, Any]:
    """
    Validates uploaded audio data for safe processing.

    Enforces:
    - Non-empty byte payload.
    - File size under max_size_mb (default: 25.0 MB).
    - Permitted file extensions (.wav, .mp3).
    - Header inspection (RIFF/WAVE for WAV, ID3/MPEG frame sync for MP3).
    - Rejection of executables, shell scripts, or arbitrary binary data disguised as audio.

    Parameters:
        file_bytes (bytes): Binary audio data.
        filename (str): Original file name.
        max_size_mb (float): Maximum allowed file size in megabytes.

    Returns:
        dict: Validation results including format, size, and error message if invalid.
    """
    if file_bytes is None:
        return {
            "is_valid": False,
            "filename": filename or "unknown",
            "file_size_bytes": 0,
            "file_size_mb": 0.0,
            "audio_format": "UNKNOWN",
            "error": "No audio file content was provided.",
        }

    if not isinstance(file_bytes, (bytes, bytearray)):
        return {
            "is_valid": False,
            "filename": filename or "unknown",
            "file_size_bytes": 0,
            "file_size_mb": 0.0,
            "audio_format": "UNKNOWN",
            "error": f"Expected binary audio bytes, but received type '{type(file_bytes).__name__}'.",
        }

    size_bytes = len(file_bytes)
    size_mb = round(size_bytes / (1024 * 1024), 2)

    if size_bytes == 0:
        return {
            "is_valid": False,
            "filename": filename or "unknown",
            "file_size_bytes": 0,
            "file_size_mb": 0.0,
            "audio_format": "UNKNOWN",
            "error": "The uploaded audio file is empty (0 bytes).",
        }

    max_bytes = int(max_size_mb * 1024 * 1024)
    if size_bytes > max_bytes:
        return {
            "is_valid": False,
            "filename": filename,
            "file_size_bytes": size_bytes,
            "file_size_mb": size_mb,
            "audio_format": "UNKNOWN",
            "error": f"File size ({size_mb} MB) exceeds the maximum limit of {max_size_mb} MB.",
        }

    # Validate file extension
    lower_name = filename.lower() if filename else ""
    matched_ext = None
    for ext in SUPPORTED_EXTENSIONS:
        if lower_name.endswith(ext):
            matched_ext = ext
            break

    if not matched_ext:
        return {
            "is_valid": False,
            "filename": filename,
            "file_size_bytes": size_bytes,
            "file_size_mb": size_mb,
            "audio_format": "UNKNOWN",
            "error": f"Unsupported audio extension '{filename}'. Allowed formats: WAV, MP3.",
        }

    # Inspect binary headers to prevent disguised files (e.g. .exe or .sh renamed to .wav)
    if matched_ext == ".wav":
        # WAV requires 'RIFF....WAVE' in first 12 bytes
        if len(file_bytes) < 12 or not (file_bytes[:4] == b"RIFF" and file_bytes[8:12] == b"WAVE"):
            return {
                "is_valid": False,
                "filename": filename,
                "file_size_bytes": size_bytes,
                "file_size_mb": size_mb,
                "audio_format": "WAV",
                "error": "Corrupted or invalid WAV file: Missing RIFF/WAVE container header.",
            }

        # Attempt opening with Python standard wave library
        try:
            with wave.open(io.BytesIO(file_bytes), "rb") as wav:
                # Check for sane audio properties
                if wav.getframerate() <= 0 or wav.getnchannels() <= 0:
                    return {
                        "is_valid": False,
                        "filename": filename,
                        "file_size_bytes": size_bytes,
                        "file_size_mb": size_mb,
                        "audio_format": "WAV",
                        "error": "Invalid WAV audio stream: Frame rate or channels must be greater than zero.",
                    }
        except Exception as e:
            return {
                "is_valid": False,
                "filename": filename,
                "file_size_bytes": size_bytes,
                "file_size_mb": size_mb,
                "audio_format": "WAV",
                "error": f"Unable to parse WAV container: {str(e)}",
            }

        return {
            "is_valid": True,
            "filename": filename,
            "file_size_bytes": size_bytes,
            "file_size_mb": size_mb,
            "audio_format": "WAV",
            "error": None,
        }

    elif matched_ext == ".mp3":
        # MP3 starts with ID3 metadata header or an MPEG frame sync (0xFF followed by high 3 bits set)
        is_id3 = file_bytes.startswith(b"ID3")
        has_frame_sync = False
        if not is_id3:
            # Check up to first 1024 bytes for MPEG sync word
            for i in range(min(1024, len(file_bytes) - 1)):
                if file_bytes[i] == 0xFF and (file_bytes[i + 1] & 0xE0) == 0xE0:
                    has_frame_sync = True
                    break

        if not (is_id3 or has_frame_sync):
            return {
                "is_valid": False,
                "filename": filename,
                "file_size_bytes": size_bytes,
                "file_size_mb": size_mb,
                "audio_format": "MP3",
                "error": "Corrupted or invalid MP3 file: Missing valid ID3 tag or MPEG sync header.",
            }

        return {
            "is_valid": True,
            "filename": filename,
            "file_size_bytes": size_bytes,
            "file_size_mb": size_mb,
            "audio_format": "MP3",
            "error": None,
        }

    return {
        "is_valid": False,
        "filename": filename,
        "file_size_bytes": size_bytes,
        "file_size_mb": size_mb,
        "audio_format": "UNKNOWN",
        "error": "Unsupported audio container.",
    }


# ---------------------------------------------------------------------------
# 2. Audio Metadata Extraction
# ---------------------------------------------------------------------------

def extract_audio_metadata(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Extracts acoustic container properties (duration, sample rate, channels, bit depth).

    Parameters:
        file_bytes (bytes): Binary audio data.
        filename (str): Name of the file.

    Returns:
        dict: Metadata dictionary.
    """
    validation = validate_audio_file(file_bytes, filename)
    if not validation["is_valid"]:
        return {
            "filename": filename,
            "format": "INVALID",
            "duration_seconds": 0.0,
            "duration_formatted": "00:00",
            "channels": 0,
            "sample_rate_hz": 0,
            "bit_depth": 0,
            "file_size_mb": validation["file_size_mb"],
            "is_valid_audio": False,
            "error": validation["error"],
        }

    fmt = validation["audio_format"]
    duration_sec = 0.0
    channels = 1
    sample_rate = 16000
    bit_depth = 16

    if fmt == "WAV":
        try:
            with wave.open(io.BytesIO(file_bytes), "rb") as wav:
                channels = wav.getnchannels()
                sample_width = wav.getsampwidth()
                bit_depth = sample_width * 8
                sample_rate = wav.getframerate()
                n_frames = wav.getnframes()
                if sample_rate > 0:
                    duration_sec = round(n_frames / float(sample_rate), 2)
        except Exception as e:
            return {
                "filename": filename,
                "format": fmt,
                "duration_seconds": 0.0,
                "duration_formatted": "00:00",
                "channels": 0,
                "sample_rate_hz": 0,
                "bit_depth": 0,
                "file_size_mb": validation["file_size_mb"],
                "is_valid_audio": False,
                "error": f"Failed extracting WAV properties: {str(e)}",
            }
    elif fmt == "MP3":
        # Estimate duration from standard 128kbps bitrate heuristic when no heavy decoder is installed
        estimated_sec = round((len(file_bytes) * 8) / (128 * 1000), 2)
        duration_sec = max(1.0, estimated_sec)
        channels = 2
        sample_rate = 44100
        bit_depth = 16

    mins = int(duration_sec // 60)
    secs = int(duration_sec % 60)
    formatted_duration = f"{mins:02d}:{secs:02d}"

    return {
        "filename": filename,
        "format": fmt,
        "duration_seconds": duration_sec,
        "duration_formatted": formatted_duration,
        "channels": channels,
        "channel_label": "Stereo" if channels == 2 else "Mono",
        "sample_rate_hz": sample_rate,
        "bit_depth": bit_depth,
        "file_size_mb": validation["file_size_mb"],
        "is_valid_audio": True,
        "error": None,
    }


# ---------------------------------------------------------------------------
# 3. Synthetic Audio Generator (Zero-Dependency Audio Synthesis for Demos & Tests)
# ---------------------------------------------------------------------------

def create_synthetic_wav(
    duration_seconds: float = 2.0,
    sample_rate: int = 16000,
    frequency_hz: float = 440.0,
) -> bytes:
    """
    Generates valid, non-empty 16-bit PCM mono WAV audio bytes in pure Python.
    Used for tests, local verification, and safe hackathon demonstration audio.

    Parameters:
        duration_seconds (float): Duration in seconds.
        sample_rate (int): Audio sample rate in Hz.
        frequency_hz (float): Sine tone frequency in Hz.

    Returns:
        bytes: Raw WAV audio container bytes.
    """
    total_frames = int(duration_seconds * sample_rate)
    buffer = io.BytesIO()

    with wave.open(buffer, "wb") as wav:
        wav.setnchannels(1)  # Mono
        wav.setsampwidth(2)  # 16-bit
        wav.setframerate(sample_rate)

        # Generate audio sine wave samples
        samples = []
        for i in range(total_frames):
            time = i / float(sample_rate)
            amplitude = 32767.0 * 0.25 * math.sin(2.0 * math.pi * frequency_hz * time)
            samples.append(int(amplitude))

        raw_frames = struct.pack("<" + "h" * len(samples), *samples)
        wav.writeframes(raw_frames)

    return buffer.getvalue()


# ---------------------------------------------------------------------------
# 4. Pluggable Transcription Backend Interface
# ---------------------------------------------------------------------------

class BaseTranscriptionBackend:
    """Abstract base class defining the speech-to-text backend interface."""

    def __init__(self, name: str):
        self.name = name

    def is_available(self) -> bool:
        """Checks if the transcription backend engine is ready in the current environment."""
        raise NotImplementedError

    def transcribe(
        self,
        file_bytes: bytes,
        filename: str,
        language: str = "auto",
    ) -> Dict[str, Any]:
        """Transcribes audio bytes to text."""
        raise NotImplementedError


class MockTranscriptionBackend(BaseTranscriptionBackend):
    """
    Deterministic mock transcription backend for unit testing and automated evaluation.
    Requires zero internet connection, external services, or model weights.
    """

    def __init__(self, default_transcript: Optional[str] = None):
        super().__init__("MockTranscriptionBackend")
        if default_transcript is not None:
            self.default_transcript = default_transcript
        else:
            self.default_transcript = (
                "This is Officer Sharma from Delhi Police Crime Branch. "
                "A digital arrest warrant has been issued against your name for an illegal parcel and money laundering. "
                "Transfer Rs 50,000 immediately to the clearance account to avoid arrest."
            )
        self.should_fail = False
        self.error_message = "Simulated transcription engine failure."

    def is_available(self) -> bool:
        return True

    def set_mock_transcript(self, text: str):
        self.default_transcript = text
        self.should_fail = False

    def trigger_failure(self, error_message: str = "Simulated transcription failure"):
        self.should_fail = True
        self.error_message = error_message

    def transcribe(
        self,
        file_bytes: bytes,
        filename: str,
        language: str = "auto",
    ) -> Dict[str, Any]:
        validation = validate_audio_file(file_bytes, filename)
        if not validation["is_valid"]:
            return {
                "success": False,
                "transcript": "",
                "confidence": 0.0,
                "language_detected": "unknown",
                "language_requested": language or "auto",
                "duration_seconds": 0.0,
                "segments": [],
                "quality_assessment": {
                    "rating": "EMPTY",
                    "score": 0.0,
                    "is_reliable": False,
                    "word_count": 0,
                    "warnings": [validation["error"]],
                    "code_switching_detected": False,
                },
                "engine_used": self.name,
                "is_real_stt": False,
                "notice": "Audio file failed validation check.",
                "error": validation["error"],
            }

        if self.should_fail:
            return {
                "success": False,
                "transcript": "",
                "confidence": 0.0,
                "language_detected": "unknown",
                "language_requested": language or "auto",
                "duration_seconds": 0.0,
                "segments": [],
                "quality_assessment": {
                    "rating": "EMPTY",
                    "score": 0.0,
                    "is_reliable": False,
                    "word_count": 0,
                    "warnings": [self.error_message],
                    "code_switching_detected": False,
                },
                "engine_used": self.name,
                "is_real_stt": False,
                "notice": "Transcription backend encountered a processing error.",
                "error": self.error_message,
            }

        norm_lang = normalize_language_code(language)
        det_lang = norm_lang or "en"
        return {
            "success": True,
            "transcript": self.default_transcript,
            "confidence": 0.95,
            "language_detected": det_lang,
            "language_probability": 0.98,
            "language_requested": language or "auto",
            "duration_seconds": 3.0,
            "segments": [
                {
                    "id": 1,
                    "start": 0.0,
                    "end": 3.0,
                    "text": self.default_transcript,
                    "avg_logprob": -0.15,
                    "no_speech_prob": 0.005,
                }
            ],
            "quality_assessment": {
                "rating": "HIGH",
                "score": 0.95,
                "is_reliable": True,
                "word_count": len(self.default_transcript.split()),
                "warnings": [],
                "code_switching_detected": False,
            },
            "engine_used": self.name,
            "is_real_stt": True,
            "notice": "Deterministic test transcription generated by MockTranscriptionBackend.",
            "error": None,
        }


class LocalSpeechRecognitionBackend(BaseTranscriptionBackend):
    """
    Hook for local offline speech recognition if installed (e.g. SpeechRecognition with local engine).
    Never transmits data to external third-party cloud APIs.
    """

    def __init__(self):
        super().__init__("LocalSpeechRecognitionBackend")
        self._sr_module = None
        self._check_availability()

    def _check_availability(self):
        try:
            import speech_recognition as sr
            self._sr_module = sr
        except ImportError:
            self._sr_module = None

    def is_available(self) -> bool:
        return self._sr_module is not None

    def transcribe(
        self,
        file_bytes: bytes,
        filename: str,
        language: str = "auto",
    ) -> Dict[str, Any]:
        if not self.is_available():
            return {
                "success": False,
                "transcript": "",
                "confidence": 0.0,
                "language_detected": "unknown",
                "engine_used": self.name,
                "is_real_stt": False,
                "notice": "Local speech-recognition package is not installed in this environment.",
                "error": "Offline speech_recognition engine not available. Please use manual transcript fallback.",
            }

        validation = validate_audio_file(file_bytes, filename)
        if not validation["is_valid"]:
            return {
                "success": False,
                "transcript": "",
                "confidence": 0.0,
                "language_detected": "unknown",
                "engine_used": self.name,
                "is_real_stt": False,
                "notice": "Invalid audio file.",
                "error": validation["error"],
            }

        sr = self._sr_module
        recognizer = sr.Recognizer()

        try:
            with sr.AudioFile(io.BytesIO(file_bytes)) as source:
                audio_data = recognizer.record(source)

            # Try offline Sphinx or local engine
            try:
                # If local sphinx is installed
                transcript = recognizer.recognize_sphinx(audio_data)
                return {
                    "success": True,
                    "transcript": transcript,
                    "confidence": 0.85,
                    "language_detected": "en-US",
                    "engine_used": "LocalSphinxEngine",
                    "is_real_stt": True,
                    "notice": "Transcribed using local offline Sphinx recognition engine.",
                    "error": None,
                }
            except Exception as sphinx_err:
                return {
                    "success": False,
                    "transcript": "",
                    "confidence": 0.0,
                    "language_detected": "unknown",
                    "engine_used": self.name,
                    "is_real_stt": False,
                    "notice": "Local acoustic speech model weights are not loaded. Please paste transcript manually.",
                    "error": f"Local recognizer error: {str(sphinx_err)}",
                }
        except Exception as err:
            return {
                "success": False,
                "transcript": "",
                "confidence": 0.0,
                "language_detected": "unknown",
                "engine_used": self.name,
                "is_real_stt": False,
                "notice": "Audio stream could not be decoded by the speech recognizer.",
                "error": str(err),
            }


def _ensure_pyav_compatibility():
    """
    Ensures compatibility between PyAV (version 14+) and audio decoding libraries.
    PyAV removed the deprecated 'metadata_errors' parameter from av.open().
    This narrow wrapper intercepts 'metadata_errors' if passed, preventing TypeErrors
    while preserving all other arguments and container functionality.
    """
    try:
        import av
        if not getattr(av, "_scamshield_patched", False):
            orig_open = av.open
            def safe_open(*args, **kwargs):
                kwargs.pop("metadata_errors", None)
                return orig_open(*args, **kwargs)
            av.open = safe_open
            av._scamshield_patched = True
    except ImportError:
        pass


class FasterWhisperTranscriptionBackend(BaseTranscriptionBackend):
    """
    Local offline speech-to-text backend powered by faster-whisper (CTranslate2).
    - Runs 100% locally on CPU (int8) or NVIDIA CUDA GPU (float16) when cuBLAS is functional.
    - Decodes WAV and MP3 in-memory via PyAV (zero external ffmpeg binary required).
    - Configurable model size (defaults to 'base', supporting 'small' or 'tiny').
    - Employs Silero VAD, anti-hallucination thresholds, and domain-targeted vocabulary prompts.
    """

    def __init__(
        self,
        model_size: Optional[str] = None,
        device: Optional[str] = None,
        compute_type: Optional[str] = None,
    ):
        chosen_model = model_size or os.getenv("SCAMSHIELD_WHISPER_MODEL", os.getenv("WHISPER_MODEL", DEFAULT_WHISPER_MODEL))
        super().__init__(f"FasterWhisperBackend({chosen_model})")
        self.model_size = chosen_model

        resolved_device, resolved_compute, resolved_desc = resolve_optimal_device(device or DEFAULT_WHISPER_DEVICE)
        self.device = resolved_device
        self.compute_type = compute_type or resolved_compute
        self.device_desc = resolved_desc
        self._model = None
        self._is_available = None
        self._init_error = None
        self._effective_model_name = chosen_model
        _ensure_pyav_compatibility()

    def is_available(self) -> bool:
        """Checks if faster-whisper is installed and can be imported."""
        if self._is_available is not None:
            return self._is_available
        try:
            import faster_whisper
            self._is_available = True
        except ImportError:
            self._is_available = False
        return self._is_available

    def _get_model(self):
        """Loads and caches the WhisperModel instance (lazy initialization with tiered fallback)."""
        if self._model is not None:
            return self._model
        if not self.is_available():
            raise RuntimeError("faster-whisper is not installed in the environment.")

        from faster_whisper import WhisperModel
        _ensure_pyav_compatibility()

        cache_key = f"{self.model_size}_{self.device}_{self.compute_type}"
        if cache_key in _LOADED_MODELS:
            self._model = _LOADED_MODELS[cache_key]
            return self._model

        # Attempt to load requested model, with offline fallback hierarchy if missing
        candidates = [self.model_size]
        for fallback in ["base", "tiny"]:
            if fallback not in candidates:
                candidates.append(fallback)

        last_error = None
        for candidate in candidates:
            try:
                model_inst = WhisperModel(
                    candidate,
                    device=self.device,
                    compute_type=self.compute_type,
                )
                self._model = model_inst
                self._effective_model_name = candidate
                _LOADED_MODELS[cache_key] = model_inst
                return self._model
            except Exception as e:
                last_error = e

        self._init_error = str(last_error)
        raise RuntimeError(f"Failed to load WhisperModel '{self.model_size}' or fallback models: {last_error}")

    def transcribe(
        self,
        file_bytes: bytes,
        filename: str,
        language: str = "auto",
    ) -> Dict[str, Any]:
        """
        Locally transcribes audio bytes without writing files to disk or contacting external APIs.
        Applies VAD filtering, disabled previous text conditioning, and domain-specific prompting.
        """
        validation = validate_audio_file(file_bytes, filename)
        if not validation["is_valid"]:
            return {
                "success": False,
                "transcript": "",
                "confidence": 0.0,
                "language_detected": "unknown",
                "language_requested": language or "auto",
                "duration_seconds": 0.0,
                "segments": [],
                "quality_assessment": {
                    "rating": "EMPTY",
                    "score": 0.0,
                    "is_reliable": False,
                    "word_count": 0,
                    "warnings": [validation["error"]],
                    "code_switching_detected": False,
                },
                "engine_used": self.name,
                "device_used": self.device,
                "is_real_stt": False,
                "notice": "Audio file failed validation check.",
                "error": validation["error"],
            }

        if not self.is_available():
            return {
                "success": False,
                "transcript": "",
                "confidence": 0.0,
                "language_detected": "unknown",
                "language_requested": language or "auto",
                "duration_seconds": 0.0,
                "segments": [],
                "quality_assessment": {
                    "rating": "EMPTY",
                    "score": 0.0,
                    "is_reliable": False,
                    "word_count": 0,
                    "warnings": ["faster-whisper package is not available."],
                    "code_switching_detected": False,
                },
                "engine_used": self.name,
                "device_used": self.device,
                "is_real_stt": False,
                "notice": "faster-whisper package is not available. Please use manual transcript fallback.",
                "error": "faster-whisper not installed.",
            }

        sig_info = inspect_audio_signal(file_bytes, filename)
        if sig_info.get("is_near_silent", False):
            return {
                "success": True,
                "transcript": "",
                "confidence": 0.0,
                "language_detected": "unknown",
                "language_requested": language or "auto",
                "duration_seconds": sig_info.get("duration_seconds", 0.0),
                "segments": [],
                "quality_assessment": {
                    "rating": "EMPTY",
                    "score": 0.0,
                    "is_reliable": False,
                    "word_count": 0,
                    "warnings": ["Audio recording appears completely silent or below recognizable acoustic threshold."],
                    "code_switching_detected": False,
                },
                "engine_used": self.name,
                "device_used": self.device,
                "is_real_stt": True,
                "notice": "Audio processed locally: no speech detected (near-silent audio signal).",
                "error": None,
            }

        try:
            model = self._get_model()
            _ensure_pyav_compatibility()

            audio_stream = io.BytesIO(file_bytes)
            norm_lang = normalize_language_code(language)
            prompt = build_domain_initial_prompt(norm_lang)

            segments, info = model.transcribe(
                audio_stream,
                language=norm_lang,
                task="transcribe",
                beam_size=1,
                best_of=1,
                temperature=0.0,
                condition_on_previous_text=False,  # CRITICAL: stops repetitive hallucination chains
                vad_filter=True,                   # CRITICAL: strips silence and line noise
                vad_parameters=dict(min_silence_duration_ms=500),
                no_speech_threshold=0.7,
                compression_ratio_threshold=2.4,
                log_prob_threshold=-1.0,
                initial_prompt=prompt,
            )

            text_chunks = []
            segment_list = []
            segment_confidences = []

            for seg in segments:
                t = seg.text.strip()
                if t:
                    text_chunks.append(t)
                try:
                    conf = math.exp(seg.avg_logprob) if seg.avg_logprob is not None else 0.8
                    segment_confidences.append(max(0.0, min(1.0, conf)))
                except Exception:
                    segment_confidences.append(0.85)

                segment_list.append({
                    "id": seg.id,
                    "start": round(seg.start, 2),
                    "end": round(seg.end, 2),
                    "text": t,
                    "avg_logprob": round(seg.avg_logprob, 3) if seg.avg_logprob is not None else None,
                    "no_speech_prob": round(seg.no_speech_prob, 3) if hasattr(seg, "no_speech_prob") else None,
                })

            full_transcript = " ".join(text_chunks).strip()
            lang_detected = getattr(info, "language", "en") or "en"
            lang_prob = float(getattr(info, "language_probability", 0.9)) if hasattr(info, "language_probability") else 0.9
            duration_sec = round(float(getattr(info, "duration", 0.0)), 2)

            avg_seg_conf = sum(segment_confidences) / len(segment_confidences) if segment_confidences else (0.0 if not full_transcript else lang_prob)
            overall_confidence = round((lang_prob * 0.4 + avg_seg_conf * 0.6), 3) if full_transcript else 0.0

            quality = evaluate_transcript_quality(
                transcript=full_transcript,
                overall_confidence=overall_confidence,
                lang_prob=lang_prob,
                detected_language=lang_detected,
                requested_language=norm_lang,
                duration_sec=duration_sec,
                is_silent=sig_info.get("is_near_silent", False),
                segments=segment_list,
            )

            # Build human notice
            lang_label = "HINDI (Devanagari)" if lang_detected == "hi" else ("ENGLISH" if lang_detected == "en" else lang_detected.upper())
            if not full_transcript:
                notice = "Audio processed locally, but no discernible speech was detected in this recording."
            else:
                notice = (
                    f"Transcribed locally using {self.name} on {self.device_desc}. "
                    f"Language: {lang_label} ({round(lang_prob * 100, 1)}% probability). "
                    f"Quality: {quality['rating']}."
                )

            return {
                "success": True,
                "transcript": full_transcript,
                "confidence": overall_confidence,
                "language_detected": lang_detected,
                "language_probability": round(lang_prob, 3),
                "language_requested": language or "auto",
                "duration_seconds": duration_sec,
                "segments": segment_list,
                "quality_assessment": quality,
                "engine_used": self.name,
                "device_used": self.device,
                "is_real_stt": True,
                "notice": notice,
                "error": None,
            }

        except Exception as e:
            return {
                "success": False,
                "transcript": "",
                "confidence": 0.0,
                "language_detected": "unknown",
                "language_requested": language or "auto",
                "duration_seconds": 0.0,
                "segments": [],
                "quality_assessment": {
                    "rating": "EMPTY",
                    "score": 0.0,
                    "is_reliable": False,
                    "word_count": 0,
                    "warnings": [f"Transcription failed: {str(e)}"],
                    "code_switching_detected": False,
                },
                "engine_used": self.name,
                "device_used": self.device,
                "is_real_stt": False,
                "notice": f"Local transcription failed: {str(e)}. Please use manual transcript review.",
                "error": str(e),
            }


class FallbackManualBackend(BaseTranscriptionBackend):
    """
    Transparent fallback backend that handles environments without heavy neural model weights.
    Provides clear error reporting and prompts the user to review audio metadata or enter transcripts manually.
    """

    def __init__(self):
        super().__init__("FallbackManualBackend")

    def is_available(self) -> bool:
        return True

    def transcribe(
        self,
        file_bytes: bytes,
        filename: str,
        language: str = "auto",
    ) -> Dict[str, Any]:
        validation = validate_audio_file(file_bytes, filename)
        if not validation["is_valid"]:
            return {
                "success": False,
                "transcript": "",
                "confidence": 0.0,
                "language_detected": "unknown",
                "language_requested": language or "auto",
                "duration_seconds": 0.0,
                "segments": [],
                "quality_assessment": {
                    "rating": "EMPTY",
                    "score": 0.0,
                    "is_reliable": False,
                    "word_count": 0,
                    "warnings": [validation["error"]],
                    "code_switching_detected": False,
                },
                "engine_used": self.name,
                "is_real_stt": False,
                "notice": "Audio file failed validation check.",
                "error": validation["error"],
            }

        meta = extract_audio_metadata(file_bytes, filename)
        return {
            "success": False,
            "transcript": "",
            "confidence": 0.0,
            "language_detected": "unknown",
            "language_requested": language or "auto",
            "duration_seconds": meta.get("duration_seconds", 0.0),
            "segments": [],
            "quality_assessment": {
                "rating": "EMPTY",
                "score": 0.0,
                "is_reliable": False,
                "word_count": 0,
                "warnings": ["No local neural speech-to-text weights available."],
                "code_switching_detected": False,
            },
            "engine_used": self.name,
            "is_real_stt": False,
            "notice": (
                f"Audio file '{filename}' ({meta['duration_formatted']}, {meta['format']}) was parsed successfully, "
                "but offline neural speech-to-text model weights (e.g., Whisper/PyTorch) are not installed in this environment. "
                "To analyze this call, please type or paste the transcript into the text area below, "
                "or load a demonstration sample."
            ),
            "error": "No local speech-to-text neural weights installed.",
        }


# ---------------------------------------------------------------------------
# 5. High-Level Audio Transcriber Manager
# ---------------------------------------------------------------------------

class AudioTranscriber:
    """
    Main manager orchestrating audio validation, metadata extraction,
    and transcription dispatch across active backends.
    """

    def __init__(
        self,
        backend: Optional[BaseTranscriptionBackend] = None,
        model_size: Optional[str] = None,
    ):
        if backend is not None:
            self.backend = backend
        else:
            target_model = model_size or DEFAULT_WHISPER_MODEL
            fw_be = FasterWhisperTranscriptionBackend(model_size=target_model)
            if fw_be.is_available():
                self.backend = fw_be
            else:
                local_be = LocalSpeechRecognitionBackend()
                if local_be.is_available():
                    self.backend = local_be
                else:
                    self.backend = FallbackManualBackend()

    def set_backend(self, backend: BaseTranscriptionBackend):
        """Swaps the active transcription backend (used for testing or model upgrades)."""
        self.backend = backend

    def transcribe(
        self,
        file_bytes: bytes,
        filename: str,
        language: str = "auto",
    ) -> Dict[str, Any]:
        """Runs validation and dispatches to the active backend."""
        val = validate_audio_file(file_bytes, filename)
        if not val["is_valid"]:
            return {
                "success": False,
                "transcript": "",
                "confidence": 0.0,
                "language_detected": "unknown",
                "language_requested": language,
                "duration_seconds": 0.0,
                "segments": [],
                "quality_assessment": {
                    "rating": "EMPTY",
                    "score": 0.0,
                    "is_reliable": False,
                    "word_count": 0,
                    "warnings": [val["error"]],
                    "code_switching_detected": False,
                },
                "engine_used": self.backend.name,
                "is_real_stt": False,
                "notice": "Audio validation failed.",
                "error": val["error"],
                "metadata": extract_audio_metadata(file_bytes, filename) if file_bytes else {},
            }

        meta = extract_audio_metadata(file_bytes, filename)
        result = self.backend.transcribe(file_bytes, filename, language=language)
        result["metadata"] = meta
        return result


# ---------------------------------------------------------------------------
# 6. Demonstration Call Presets (Synthetic Audio + Reference Transcripts)
# ---------------------------------------------------------------------------

DEMO_CALL_PRESETS = [
    {
        "id": "demo_call_01",
        "title": "🚨 Call 1: Delhi Police Digital Arrest Extortion",
        "filename": "delhi_police_digital_arrest.wav",
        "caller_label": "Claimed: Officer Vikram Sharma (Delhi Police Crime Branch)",
        "tone_frequency": 350.0,
        "duration_sec": 4.0,
        "transcript": (
            "This is Officer Vikram Sharma from Delhi Police Crime Branch. "
            "A digital arrest warrant has been issued against your name for an illegal parcel and money laundering. "
            "Transfer Rs 50,000 immediately to the clearance account to unfreeze your identity, "
            "or police officers will be dispatched within 30 minutes. Do not disconnect the video call."
        ),
        "expected_risk": "HIGH",
        "threat_category": "Authority Impersonation & Digital Arrest",
    },
    {
        "id": "demo_call_02",
        "title": "📦 Call 2: Customs Courier Contraband Clearance Threat",
        "filename": "fedex_customs_contraband.wav",
        "caller_label": "Claimed: Mumbai Customs Clearance Hub",
        "tone_frequency": 440.0,
        "duration_sec": 3.5,
        "transcript": (
            "This is FedEx Courier Mumbai hub. An international parcel containing illegal passports and drugs "
            "in your name is seized by Customs. Pay clearance penalty of Rs 35,000 to UPI ID customs.fine@sbi "
            "immediately to avoid arrest and court summons."
        ),
        "expected_risk": "HIGH",
        "threat_category": "Courier Parcel Extortion",
    },
    {
        "id": "demo_call_03",
        "title": "💳 Call 3: Bank KYC Account Suspension & OTP Phishing",
        "filename": "sbi_kyc_suspension_otp.wav",
        "caller_label": "Claimed: SBI Verification Department",
        "tone_frequency": 520.0,
        "duration_sec": 3.0,
        "transcript": (
            "URGENT NOTICE: Your SBI bank account will be blocked within 2 hours due to expired KYC verification. "
            "Please share your 6-digit OTP and NetBanking password immediately to avoid permanent deactivation."
        ),
        "expected_risk": "HIGH",
        "threat_category": "Banking OTP Phishing",
    },
    {
        "id": "demo_call_04",
        "title": "⚡ Call 4: State Electricity Board Urgent Power Cutoff",
        "filename": "bijli_office_urgent_cutoff.wav",
        "caller_label": "Claimed: State Electricity Board Helpline",
        "tone_frequency": 400.0,
        "duration_sec": 3.0,
        "transcript": (
            "Urgent Notice from State Electricity Board: Pay your pending power bill of Rs 4,800 within 2 hours "
            "or your electricity connection will be cut permanently. Pay via UPI: power.bill@sbi"
        ),
        "expected_risk": "HIGH",
        "threat_category": "Utility Disconnection Extortion",
    },
    {
        "id": "demo_call_05",
        "title": "☕ Call 5: Normal Friend Call (Benign Reference)",
        "filename": "friend_lunch_coffee.wav",
        "caller_label": "Friend / Colleague",
        "tone_frequency": 480.0,
        "duration_sec": 2.5,
        "transcript": (
            "Hey! Are we still meeting for lunch at 1 PM today? Let me know if you want to grab coffee afterwards. "
            "Talk to you later!"
        ),
        "expected_risk": "LOW",
        "threat_category": "Harmless Everyday Call",
        "language": "en",
    },
    {
        "id": "demo_call_06",
        "title": "🚨 Call 6: CBI Digital Arrest Extortion (हिंदी / Hinglish)",
        "filename": "cbi_hindi_digital_arrest.wav",
        "caller_label": "Claimed: CBI Cyber Crime Cell (New Delhi)",
        "tone_frequency": 380.0,
        "duration_sec": 4.5,
        "transcript": (
            "यह सीबीआई साइबर सेल नई दिल्ली से इंस्पेक्टर शर्मा हैं। "
            "आपके आधार कार्ड पर एक अवैध पार्सल और मनी लॉन्ड्रिंग का डिजिटल अरेस्ट वारंट जारी हुआ है। "
            "तुरंत पचास हजार रुपये क्लियरेंस खाते में ट्रांसफर करें अन्यथा पुलिस टीम आपके घर पहुंचेगी।"
        ),
        "expected_risk": "HIGH",
        "threat_category": "Hindi Authority Impersonation & Digital Arrest",
        "language": "hi",
    },
]


def get_sample_call_presets() -> List[Dict[str, Any]]:
    """
    Returns the list of curated demo audio call presets.
    Generates synthetic WAV audio in memory on demand.
    """
    presets = []
    for item in DEMO_CALL_PRESETS:
        # Generate valid synthetic WAV bytes for audio playback
        audio_bytes = create_synthetic_wav(
            duration_seconds=item["duration_sec"],
            sample_rate=16000,
            frequency_hz=item["tone_frequency"],
        )
        entry = dict(item)
        entry["audio_bytes"] = audio_bytes
        entry["file_size_bytes"] = len(audio_bytes)
        entry["file_size_mb"] = round(len(audio_bytes) / (1024 * 1024), 2)
        presets.append(entry)
    return presets
