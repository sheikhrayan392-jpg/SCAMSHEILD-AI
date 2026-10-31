import sys
import io
import time
from faster_whisper import WhisperModel

sys.stdout.reconfigure(line_buffering=True)

from audio_transcription import _ensure_pyav_compatibility
_ensure_pyav_compatibility()

wav_path = r"C:\Users\VICTUS\Downloads\normal_voice.wav"
print(f"Loading {wav_path}...")

with open(wav_path, "rb") as f:
    audio_bytes = f.read()

print("Loading base model...")
t0 = time.time()
model = WhisperModel("base", device="cpu", compute_type="int8")
print(f"Model loaded in {time.time()-t0:.2f}s")

# Let's inspect raw audio decoding
import av
print("Inspecting audio with av...")
with av.open(io.BytesIO(audio_bytes)) as container:
    for stream in container.streams:
        print(f"Stream: {stream.type}, rate={getattr(stream, 'rate', None)}, channels={getattr(stream, 'channels', None)}, format={getattr(stream, 'format', None)}")

# Test 1: transcribe without VAD, without prompt, auto detect
print("\n--- Test 1: Raw transcribe, auto detect, no VAD, no prompt, beam_size=1 ---")
t0 = time.time()
segments, info = model.transcribe(io.BytesIO(audio_bytes), beam_size=1)
print(f"Info: lang={info.language}, prob={info.language_probability}, dur={info.duration}")
for s in segments:
    print(f"[{s.start:.2f} - {s.end:.2f}] (no_speech={s.no_speech_prob:.2f}): {s.text}")
print(f"Done in {time.time()-t0:.2f}s")

# Test 2: transcribe without VAD, without prompt, language='hi', beam_size=1
print("\n--- Test 2: Raw transcribe, language='hi', no VAD, no prompt, beam_size=1 ---")
t0 = time.time()
segments, info = model.transcribe(io.BytesIO(audio_bytes), language="hi", beam_size=1)
print(f"Info: lang={info.language}, prob={info.language_probability}, dur={info.duration}")
for s in segments:
    print(f"[{s.start:.2f} - {s.end:.2f}] (no_speech={s.no_speech_prob:.2f}): {s.text}")
print(f"Done in {time.time()-t0:.2f}s")
