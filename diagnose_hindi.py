import sys
import time
import io

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

from audio_transcription import _ensure_pyav_compatibility
_ensure_pyav_compatibility()

from faster_whisper import WhisperModel
from faster_whisper.audio import decode_audio

wav_path = r"C:\Users\VICTUS\Downloads\normal_voice.wav"
print(f"Decoding {wav_path}...")
with open(wav_path, "rb") as f:
    wav_bytes = f.read()

arr = decode_audio(io.BytesIO(wav_bytes), sampling_rate=16000)
print(f"Audio shape: {arr.shape}, duration={len(arr)/16000:.2f}s")

# Let's test with tiny model first (fastest)
print("\n=== Testing TINY model ===")
model_tiny = WhisperModel("tiny", device="cpu", compute_type="int8")

print("\n[Tiny] 1. Auto-detect, no prompt, no vad:")
t0 = time.time()
segs, info = model_tiny.transcribe(arr, language=None, beam_size=1)
print(f"Detected: {info.language} ({info.language_probability:.3f})")
for s in segs:
    print(f"  [{s.start:.1f}-{s.end:.1f}] {s.text}")
print(f"Time: {time.time()-t0:.2f}s")

print("\n[Tiny] 2. Forced Hindi (hi), no prompt, no vad:")
t0 = time.time()
segs, info = model_tiny.transcribe(arr, language="hi", beam_size=1)
print(f"Detected: {info.language} ({info.language_probability:.3f})")
for s in segs:
    print(f"  [{s.start:.1f}-{s.end:.1f}] {s.text}")
print(f"Time: {time.time()-t0:.2f}s")

# Let's test with base model
print("\n=== Testing BASE model ===")
model_base = WhisperModel("base", device="cpu", compute_type="int8")

print("\n[Base] 1. Auto-detect, no prompt, no vad:")
t0 = time.time()
segs, info = model_base.transcribe(arr, language=None, beam_size=1)
print(f"Detected: {info.language} ({info.language_probability:.3f})")
for s in segs:
    print(f"  [{s.start:.1f}-{s.end:.1f}] {s.text}")
print(f"Time: {time.time()-t0:.2f}s")

print("\n[Base] 2. Forced Hindi (hi), no prompt, no vad:")
t0 = time.time()
segs, info = model_base.transcribe(arr, language="hi", beam_size=1)
print(f"Detected: {info.language} ({info.language_probability:.3f})")
for s in segs:
    print(f"  [{s.start:.1f}-{s.end:.1f}] {s.text}")
print(f"Time: {time.time()-t0:.2f}s")
