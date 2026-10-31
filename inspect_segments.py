import sys
import io

from audio_transcription import _ensure_pyav_compatibility
_ensure_pyav_compatibility()
from faster_whisper import WhisperModel

m = WhisperModel('small', device='cpu', compute_type='int8')
wav_file = r'C:\Users\VICTUS\Downloads\normal_voice.wav'

print("--- Testing segments with language='hi' ---")
segs, info = m.transcribe(wav_file, language="hi", beam_size=1, temperature=0.0)
for s in segs:
    print(f"Segment [{s.start:.2f} - {s.end:.2f}] (no_speech={s.no_speech_prob:.2f}, avg_logprob={s.avg_logprob:.2f}): \"{s.text}\"")

print("\n--- Testing segments with language='hi' and vad_filter=True ---")
segs, info = m.transcribe(wav_file, language="hi", beam_size=1, temperature=0.0, vad_filter=True)
for s in segs:
    print(f"VAD Segment [{s.start:.2f} - {s.end:.2f}] (no_speech={s.no_speech_prob:.2f}, avg_logprob={s.avg_logprob:.2f}): \"{s.text}\"")
