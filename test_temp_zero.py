import sys
import time
import io
import math

from audio_transcription import _ensure_pyav_compatibility
_ensure_pyav_compatibility()

from faster_whisper import WhisperModel
from faster_whisper.audio import decode_audio

wav_path = r"C:\Users\VICTUS\Downloads\normal_voice.wav"
with open(wav_path, "rb") as f:
    wav_bytes = f.read()

arr = decode_audio(io.BytesIO(wav_bytes), sampling_rate=16000)
print(f"Decoded {len(arr)} samples ({len(arr)/16000:.2f}s)")

# Load base model
print("Loading base model...")
model = WhisperModel("base", device="cpu", compute_type="int8", cpu_threads=4)

print("\n--- TEST: Forced Hindi (hi) with temperature=0.0, beam_size=1 ---")
t0 = time.time()
segs, info = model.transcribe(
    arr,
    language="hi",
    task="transcribe",
    beam_size=1,
    best_of=1,
    temperature=0.0,
    condition_on_previous_text=False,
    vad_filter=False,
)
print(f"Lang: {info.language} ({info.language_probability:.2f}), Duration: {info.duration:.2f}s")
segments_list = list(segs)
print(f"Decoded {len(segments_list)} segments in {time.time()-t0:.2f}s:")
for s in segments_list:
    print(f"  [{s.start:.2f} - {s.end:.2f}] (prob={math.exp(s.avg_logprob) if s.avg_logprob else 0:.2f}): {s.text}")

print("\n--- TEST: Forced Hindi (hi) with vad_filter=True, temperature=0.0 ---")
t0 = time.time()
segs_vad, info_vad = model.transcribe(
    arr,
    language="hi",
    task="transcribe",
    beam_size=1,
    best_of=1,
    temperature=0.0,
    condition_on_previous_text=False,
    vad_filter=True,
    vad_parameters=dict(min_silence_duration_ms=500),
)
print(f"Lang: {info_vad.language} ({info_vad.language_probability:.2f})")
segments_vad = list(segs_vad)
print(f"Decoded {len(segments_vad)} segments in {time.time()-t0:.2f}s:")
for s in segments_vad:
    print(f"  [{s.start:.2f} - {s.end:.2f}]: {s.text}")
