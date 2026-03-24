# python -m pip install pydub
# python -m pip install ffmpeg-python

# Download ffmpeg for Windows (needed for m4a conversion)
# Go to: https://ffmpeg.org/download.html
# Download the Windows build, extract it
# Add the bin folder to PATH, OR just use this approach:

import librosa
import soundfile as sf
from pathlib import Path

# Force load with audioread and save as proper wav
y, sr = librosa.load('outputs/real2.m4a', sr=16000, mono=True)
sf.write('outputs/real2.wav', y, 16000)
print(f'Converted — samples: {len(y)}  duration: {len(y)/16000:.1f}s')
print('Saved → outputs/real1.wav')
