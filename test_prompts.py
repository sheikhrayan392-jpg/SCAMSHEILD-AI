import sys
from audio_transcription import _ensure_pyav_compatibility
_ensure_pyav_compatibility()
from faster_whisper import WhisperModel

wav_file = r'C:\Users\VICTUS\Downloads\normal_voice_16k.wav'

for model_name in ["base", "small"]:
    print(f"\n=================== MODEL: {model_name} ===================")
    m = WhisperModel(model_name, device="cpu", compute_type="int8")

    prompts = [
        None,
        "नमस्ते भाई, कैसे हो? क्या हाल है?",
        "Namaste bhai, kaise ho? College schedule notes lunch break.",
    ]
    for p in prompts:
        print(f"\n--- Testing language='hi', prompt={p!r} ---")
        segs, info = m.transcribe(
            wav_file,
            language="hi",
            initial_prompt=p,
            beam_size=5,
            best_of=5,
            temperature=0.0,
            condition_on_previous_text=False,
            vad_filter=True,
        )
        text = " ".join(s.text.strip() for s in segs)
        print(f"Output: \"{text}\"")

    for p in prompts:
        print(f"\n--- Testing language='en', prompt={p!r} ---")
        segs, info = m.transcribe(
            wav_file,
            language="en",
            initial_prompt=p,
            beam_size=5,
            best_of=5,
            temperature=0.0,
            condition_on_previous_text=False,
            vad_filter=True,
        )
        text = " ".join(s.text.strip() for s in segs)
        print(f"Output: \"{text}\"")
