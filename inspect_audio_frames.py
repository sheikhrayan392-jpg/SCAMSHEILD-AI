import av
import io
import numpy as np

with open(r"C:\Users\VICTUS\Downloads\normal_voice.wav", "rb") as f:
    b = f.read()

container = av.open(io.BytesIO(b))
print("Container:", container)
for s in container.streams:
    print(f"Stream: {s}, rate={s.rate}, time_base={s.time_base}, duration={s.duration}")

frames = []
for frame in container.decode(audio=0):
    frames.append(frame)

print(f"Total frames: {len(frames)}")
if frames:
    print(f"Frame 0: pts={frames[0].pts}, time={frames[0].time}, rate={frames[0].rate}, samples={frames[0].samples}")
    print(f"Frame -1: pts={frames[-1].pts}, time={frames[-1].time}, rate={frames[-1].rate}, samples={frames[-1].samples}")

# Now let's check faster_whisper decode_audio
from faster_whisper.audio import decode_audio
resampled = decode_audio(io.BytesIO(b), sampling_rate=16000)
print(f"Resampled length: {len(resampled)} samples ({len(resampled)/16000:.2f}s)")
