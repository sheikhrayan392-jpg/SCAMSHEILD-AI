import io
import wave
import numpy as np
from faster_whisper.audio import decode_audio

from audio_transcription import _ensure_pyav_compatibility
_ensure_pyav_compatibility()

with open(r"C:\Users\VICTUS\Downloads\normal_voice.wav", "rb") as f:
    b = f.read()

arr = decode_audio(io.BytesIO(b), sampling_rate=16000)
# Save resampled audio as 16kHz WAV
out_16k = r"C:\Users\VICTUS\Downloads\normal_voice_16k.wav"
with wave.open(out_16k, "wb") as w:
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(16000)
    w.writeframes((arr * 32767).astype(np.int16).tobytes())

print(f"Saved {out_16k}: {len(arr)} samples, {len(arr)/16000:.2f}s")
