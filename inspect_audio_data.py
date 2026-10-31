import wave
import struct
import numpy as np

wav_path = r"C:\Users\VICTUS\Downloads\normal_voice.wav"
with wave.open(wav_path, "rb") as w:
    params = w.getparams()
    frames = w.readframes(w.getnframes())

print(f"Params: {params}")
samples = np.frombuffer(frames, dtype=np.int16)
print(f"Total samples: {len(samples)}")
print(f"Min: {np.min(samples)}, Max: {np.max(samples)}, Mean: {np.mean(samples)}, Std: {np.std(samples)}")
print(f"Duration: {len(samples)/params.framerate:.2f}s")

# Let's inspect energy in 1-second chunks
chunk_size = params.framerate
for i in range(0, len(samples), chunk_size):
    chunk = samples[i:i+chunk_size]
    rms = np.sqrt(np.mean(chunk.astype(float)**2))
    print(f"Sec {i//chunk_size}: RMS={rms:.1f}, Max={np.max(np.abs(chunk))}")
