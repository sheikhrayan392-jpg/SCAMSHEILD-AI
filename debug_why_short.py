import sys
import io

from audio_transcription import _ensure_pyav_compatibility
_ensure_pyav_compatibility()
from faster_whisper import WhisperModel
from faster_whisper.audio import decode_audio

wav_file = r'C:\Users\VICTUS\Downloads\normal_voice.wav'
with open(wav_file, "rb") as f:
    b = f.read()

arr = decode_audio(io.BytesIO(b), sampling_rate=16000)
print(f"Total audio: {len(arr)} samples = {len(arr)/16000:.2f}s")

# Let's slice the first 10 seconds of the audio
arr_first_10s = arr[:16000*10]
# And the second 10 seconds
arr_second_10s = arr[16000*9:]

m = WhisperModel("base", device="cpu", compute_type="int8")

print("\n--- Slicing: First 10 seconds (0s - 10s) with language='hi' ---")
segs1, _ = m.transcribe(arr_first_10s, language="hi", beam_size=1, temperature=0.0)
for s in segs1:
    print(f"  [{s.start:.2f}-{s.end:.2f}] (no_speech={s.no_speech_prob:.2f}): {s.text}")

print("\n--- Slicing: Second 10 seconds (9s - 19.4s) with language='hi' ---")
segs2, _ = m.transcribe(arr_second_10s, language="hi", beam_size=1, temperature=0.0)
for s in segs2:
    print(f"  [{s.start:.2f}-{s.end:.2f}] (no_speech={s.no_speech_prob:.2f}): {s.text}")
