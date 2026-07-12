import mido

mid = mido.MidiFile('/home/nata/ctf/JuniorCrypt/misc/1000-7/chal.mid')
pws = [msg.pitch for msg in mid.tracks[1] if msg.type == 'pitchwheel']
bits = ''.join('1' if pws[i] == 2304 else '0' for i in range(0, len(pws), 2))
flag_bytes = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
# Extract grodno{...} from bytes
start = flag_bytes.find(b'grodno{')
end = flag_bytes.find(b'}', start) + 1
flag = flag_bytes[start:end].decode('utf-8')
print(flag)
