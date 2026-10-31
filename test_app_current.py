from audio_transcription import FasterWhisperTranscriptionBackend

with open(r"C:\Users\VICTUS\Downloads\normal_voice.wav", "rb") as f:
    b = f.read()

backend = FasterWhisperTranscriptionBackend(model_size="base")

print("--- Testing backend with language='auto' ---")
res_auto = backend.transcribe(b, "normal_voice.wav", language="auto")
print("AUTO Transcript:", res_auto["transcript"])
print("AUTO Detected lang:", res_auto["language_detected"])

print("\n--- Testing backend with language='hi' ---")
res_hi = backend.transcribe(b, "normal_voice.wav", language="hi")
print("HI Transcript:", res_hi["transcript"])
print("HI Detected lang:", res_hi["language_detected"])
