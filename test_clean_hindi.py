import sys
import time
import io

from audio_transcription import _ensure_pyav_compatibility
_ensure_pyav_compatibility()
from faster_whisper import WhisperModel
from faster_whisper.audio import decode_audio

wav_file = r'C:\Users\VICTUS\Downloads\normal_voice.wav'
with open(wav_file, "rb") as f:
    b = f.read()

arr = decode_audio(io.BytesIO(b), sampling_rate=16000)

for model_size in ["base", "small"]:
    print(f"\n=================== MODEL: {model_size} ===================")
    m = WhisperModel(model_size, device="cpu", compute_type="int8", cpu_threads=4)

    # Test 1: temperature=0.0, beam_size=1, concise prompt
    t0 = time.time()
    segs, info = m.transcribe(
        arr,
        language="hi",
        task="transcribe",
        beam_size=1,
        best_of=1,
        temperature=0.0,
        condition_on_previous_text=False,
        vad_filter=True,
        initial_prompt="नमस्ते, कैसे हो? कॉलेज, शेड्यूल, नोट्स, लंच, बाय।",
    )
    text = " ".join(s.text.strip() for s in segs)
    print(f"[Prompt in Hindi Devanagari] [{time.time()-t0:.1f}s]:\n  \"{text}\"")

    # Test 2: temperature=0.0, beam_size=1, prompt in Latin Hindi / Hinglish
    t0 = time.time()
    segs, info = m.transcribe(
        arr,
        language="hi",
        task="transcribe",
        beam_size=1,
        best_of=1,
        temperature=0.0,
        condition_on_previous_text=False,
        vad_filter=True,
        initial_prompt="Namaste, kaise ho? College schedule, notes, lunch break, bye.",
    )
    text = " ".join(s.text.strip() for s in segs)
    print(f"[Prompt in Hinglish] [{time.time()-t0:.1f}s]:\n  \"{text}\"")

    # Test 3: No initial prompt
    t0 = time.time()
    segs, info = m.transcribe(
        arr,
        language="hi",
        task="transcribe",
        beam_size=1,
        best_of=1,
        temperature=0.0,
        condition_on_previous_text=False,
        vad_filter=True,
        initial_prompt=None,
    )
    text = " ".join(s.text.strip() for s in segs)
    print(f"[No Prompt] [{time.time()-t0:.1f}s]:\n  \"{text}\"")
