from audio_transcription import _ensure_pyav_compatibility
_ensure_pyav_compatibility()
from faster_whisper import WhisperModel
import time

m = WhisperModel('small', device='cpu', compute_type='int8')
wav_file = r'C:\Users\VICTUS\Downloads\normal_voice.wav'

for lang in [None, 'hi', 'en']:
    t0 = time.time()
    segs, info = m.transcribe(wav_file, language=lang, beam_size=1, temperature=0.0)
    text = ' '.join(s.text for s in segs)
    print(f"Lang={lang} -> Detected={info.language} ({info.language_probability:.2f}) [{time.time()-t0:.1f}s]: \"{text}\"")
