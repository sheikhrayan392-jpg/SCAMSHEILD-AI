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

for model_name in ["base", "small"]:
    print(f"\n=================== MODEL: {model_name} ===================")
    m = WhisperModel(model_name, device="cpu", compute_type="int8")
    
    # Test 1: Standard Whisper defaults for language='hi'
    print("\n--- Test: language='hi', defaults ---")
    segs, info = m.transcribe(arr, language="hi")
    for s in segs:
        print(f"[{s.start:.2f}-{s.end:.2f}] (no_speech={s.no_speech_prob:.2f}, avg_logprob={s.avg_logprob:.2f}): {s.text}")

    # Test 2: language='hi' with prompt='नमस्ते'
    print("\n--- Test: language='hi', prompt='नमस्ते, कैसे हो?' ---")
    segs, info = m.transcribe(arr, language="hi", initial_prompt="नमस्ते, कैसे हो?")
    for s in segs:
        print(f"[{s.start:.2f}-{s.end:.2f}]: {s.text}")

    # Test 3: language=None (auto-detect) with prompt in Hindi
    print("\n--- Test: auto-detect with prompt='नमस्ते' ---")
    segs, info = m.transcribe(arr, initial_prompt="नमस्ते, कैसे हो?")
    print(f"Auto detected: {info.language} ({info.language_probability:.2f})")
    for s in segs:
        print(f"[{s.start:.2f}-{s.end:.2f}]: {s.text}")
