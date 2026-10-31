import sys
import os

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

from audio_transcription import (
    AudioTranscriber,
    extract_audio_metadata,
    inspect_audio_signal,
    FasterWhisperTranscriptionBackend,
)

audio_file = r"C:\Users\VICTUS\Downloads\normal_voice.wav"
print(f"Reading {audio_file}...")

with open(audio_file, "rb") as f:
    wav_bytes = f.read()

print(f"Read {len(wav_bytes)} bytes.")

meta = extract_audio_metadata(wav_bytes, "normal_voice.wav")
print(f"Metadata: {meta}")

sig = inspect_audio_signal(wav_bytes, "normal_voice.wav")
print(f"Signal: {sig}")

transcriber = AudioTranscriber()
backend = transcriber.backend
print(f"Active Backend: {backend.name}, Model: {getattr(backend, 'model_size', None)}, Device: {getattr(backend, 'device', None)}")

print("\n--- TEST 1: AUTO DETECT ---")
res_auto = transcriber.transcribe(wav_bytes, "normal_voice.wav", language="auto")
print(f"Auto Success: {res_auto['success']}")
print(f"Detected Lang: {res_auto.get('language_detected')} ({res_auto.get('language_probability')})")
print(f"Transcript: {res_auto.get('transcript')}")
print(f"Segments: {res_auto.get('segments')}")
print(f"Quality: {res_auto.get('quality_assessment')}")

print("\n--- TEST 2: FORCED HINDI (hi) ---")
res_hi = transcriber.transcribe(wav_bytes, "normal_voice.wav", language="hi")
print(f"Hindi Success: {res_hi['success']}")
print(f"Detected Lang: {res_hi.get('language_detected')} ({res_hi.get('language_probability')})")
print(f"Transcript: {res_hi.get('transcript')}")
print(f"Segments: {res_hi.get('segments')}")
print(f"Quality: {res_hi.get('quality_assessment')}")
