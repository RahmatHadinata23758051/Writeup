# solve.py - Operation Conductor Part 1
import wave
import numpy as np
import re

def solve():
    with wave.open('secret.wav', 'r') as w:
        frames = w.readframes(w.getnframes())
    
    samples = np.frombuffer(frames, dtype=np.int16)
    
    # Setiap sample menyimpan nibble hex (0-15)
    # Encoding: cluster = (sample - 1000) // 750
    nibbles = [(int(s) - 1000) // 750 for s in samples]
    hex_str = ''.join(f'{n:x}' for n in nibbles)
    raw = bytes.fromhex(hex_str)
    
    for m in re.finditer(b'LNC26\{[^\}]+\}', raw):
        print('FLAG:', m.group().decode())

if __name__ == '__main__':
    solve()
