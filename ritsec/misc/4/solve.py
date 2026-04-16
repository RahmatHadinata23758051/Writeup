#!/usr/bin/env python3
"""
Sargasso Static - FHSS Wideband Solver
---------------------------------------
The capture is WIDEBAND (2.4 MHz BW) containing ALL hop channels simultaneously.
The LFSR defines which freq channel each time slot uses.
We bandpass-filter each slot to its channel, demodulate, then parse packets.

Key parameters to discover:
  - Number of channels (N)
  - Channel spacing (BW / N)  
  - Dwell time per hop (samples)
  - Modulation type + baud rate
  - LFSR seed

Usage: python3 solve_fhss.py capture.cf2
"""

import numpy as np
import struct
import sys
import os
import crcmod
from scipy import signal as sp_signal

SAMPLE_RATE   = 2_400_000
CAPTURE_SECS  = 10.0
N_IQ_SAMPLES  = 24_000_000

crc16_fn = crcmod.predefined.mkCrcFun('crc-ccitt-false')

# ---------------------------------------------------------------------------
# LFSR  (x^24 + x^23 + x^22 + x^17 + 1, Galois)
# ---------------------------------------------------------------------------
LFSR_MASK = (1 << 23) | (1 << 22) | (1 << 21) | (1 << 16)

def lfsr_next(state):
    lsb = state & 1
    state >>= 1
    if lsb:
        state ^= LFSR_MASK
    return state & 0xFFFFFF

def lfsr_seq(seed, n):
    s, out = seed, []
    for _ in range(n):
        out.append(s)
        s = lfsr_next(s)
    return out

# ---------------------------------------------------------------------------
# Packet parser
# ---------------------------------------------------------------------------
def find_packets(data: bytes):
    pkts, i, n = [], 0, len(data)
    while i < n - 8:
        if data[i] == 0xAD and data[i+1] == 0xDE:
            seq = data[i+2]
            typ = data[i+3]
            ln  = struct.unpack_from('<H', data, i+4)[0]
            end = i + 6 + ln + 2
            if end <= n and ln <= 4096:
                pl  = data[i+6:i+6+ln]
                crc = struct.unpack_from('<H', data, i+6+ln)[0]
                if crc16_fn(data[i+2:i+6+ln]) == crc:
                    pkts.append({'offset':i,'seq':seq,'type':typ,'length':ln,'payload':pl})
                    i = end; continue
        i += 1
    return pkts

# ---------------------------------------------------------------------------
# DSP utilities
# ---------------------------------------------------------------------------
def make_bandpass(center_hz, bw_hz, fs, numtaps=127):
    """FIR bandpass (complex mix-down approach: just shift then LP)."""
    lo = center_hz - bw_hz / 2
    hi = center_hz + bw_hz / 2
    lo_n = max(abs(lo), 1) / (fs / 2)
    hi_n = min(abs(hi), fs/2 - 1) / (fs / 2)
    return sp_signal.firwin(numtaps, [lo_n, hi_n], pass_zero=False)

def mix_and_filter(iq, center_hz, channel_bw, fs):
    """
    Mix IQ down so center_hz becomes DC, then low-pass filter to channel_bw/2.
    Returns complex baseband signal for one channel.
    """
    t = np.arange(len(iq)) / fs
    # Mix down
    lo = np.exp(-2j * np.pi * center_hz * t)
    mixed = iq * lo
    # Low-pass filter
    cutoff = channel_bw * 0.45 / (fs / 2)
    cutoff = min(cutoff, 0.999)
    taps = sp_signal.firwin(63, cutoff)
    bb = sp_signal.lfilter(taps, 1.0, mixed)
    return bb

def fm_demod(bb, fs, baud):
    """FM discriminator → symbols → bits."""
    dph = np.angle(bb[1:] * np.conj(bb[:-1]))
    inst_f = dph * fs / (2 * np.pi)
    sps = max(1, int(fs / baud))
    # Low-pass to symbol rate
    b = sp_signal.firwin(min(sps * 4 + 1, 63), baud * 0.45 / (fs / 2))
    filtered = sp_signal.lfilter(b, 1.0, inst_f)
    # Sample at center of each symbol
    syms = filtered[sps // 2::sps]
    bits = (syms > np.median(syms)).astype(np.uint8)
    return bits

def bits2bytes(bits, lsb=False):
    n = (len(bits) // 8) * 8
    out = bytearray()
    for i in range(0, n, 8):
        b = 0
        chunk = bits[i:i+8]
        if lsb:
            for j, v in enumerate(chunk): b |= int(v) << j
        else:
            for v in chunk: b = (b << 1) | int(v)
        out.append(b)
    return bytes(out)

# ---------------------------------------------------------------------------
# Wideband spectrum scan — find occupied channels
# ---------------------------------------------------------------------------
def scan_channels(iq, fs, n_fft=32768, n_chunks=50):
    """Average PSD over several chunks to find where signals are."""
    print(f"[*] Scanning wideband spectrum ({n_chunks} chunks x {n_fft} FFT)...")
    step = max(1, len(iq) // n_chunks)
    psd_avg = np.zeros(n_fft)
    for i in range(n_chunks):
        idx = i * step
        chunk = iq[idx:idx+n_fft]
        if len(chunk) < n_fft:
            break
        psd_avg += np.abs(np.fft.fft(chunk))**2
    psd_avg /= n_chunks
    psd_avg = np.fft.fftshift(psd_avg)
    freqs = np.fft.fftshift(np.fft.fftfreq(n_fft, 1/fs))
    
    # Smooth
    psd_smooth = np.convolve(psd_avg, np.ones(32)/32, mode='same')
    
    # Find peaks
    threshold = np.percentile(psd_smooth, 75)
    peaks, props = sp_signal.find_peaks(psd_smooth, height=threshold, distance=50)
    print(f"    Found {len(peaks)} spectral peaks:")
    peak_freqs = []
    for pk in peaks[:20]:
        print(f"      {freqs[pk]/1e3:+7.1f} kHz  power={10*np.log10(psd_smooth[pk]):.1f} dB")
        peak_freqs.append(freqs[pk])
    
    return freqs, psd_avg, sorted(peak_freqs)

# ---------------------------------------------------------------------------
# Auto-detect dwell time by looking at spectral power vs time
# ---------------------------------------------------------------------------
def detect_dwell(iq, fs, center_freq, channel_bw, n_test=2000):
    """
    Track power in one channel over time to detect when hops occur.
    """
    print(f"[*] Detecting hop dwell time on channel {center_freq/1e3:.1f} kHz...")
    # Mix to channel
    chunk_size = 256
    powers = []
    t = np.arange(chunk_size) / fs
    lo_base = np.exp(-2j * np.pi * center_freq / fs)
    
    for i in range(min(n_test, len(iq)//chunk_size)):
        seg = iq[i*chunk_size:(i+1)*chunk_size]
        # Power in channel (simple: abs squared mean)
        ph = np.exp(-2j * np.pi * center_freq * np.arange(i*chunk_size, (i+1)*chunk_size) / fs)
        mixed = seg * ph
        power = np.mean(np.abs(mixed)**2)
        powers.append(power)
    
    powers = np.array(powers)
    # Detect on/off transitions
    threshold = (powers.max() + powers.min()) / 2
    on_mask = powers > threshold
    # Find transitions
    transitions = np.where(np.diff(on_mask.astype(int)) != 0)[0]
    if len(transitions) > 2:
        dwell_chunks = np.median(np.diff(transitions))
        dwell_samples = int(dwell_chunks * chunk_size)
        print(f"    Estimated dwell: {dwell_chunks:.0f} chunks = "
              f"{dwell_samples} samples = {dwell_samples/fs*1000:.1f} ms")
        return dwell_samples
    return None

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    filepath = sys.argv[1] if len(sys.argv) > 1 else 'capture.cf2'
    if not os.path.exists(filepath):
        print(f"[!] {filepath} not found"); return

    print(f"[*] Loading {filepath} ...")
    raw = np.fromfile(filepath, dtype=np.float32)
    iq  = raw[0::2] + 1j * raw[1::2]
    print(f"[*] {len(iq):,} IQ samples @ {SAMPLE_RATE/1e6:.2f} MS/s  "
          f"(power={10*np.log10(np.mean(np.abs(iq)**2)):.1f} dBFS)")

    # ---- 1. Wideband spectrum scan ----
    freqs, psd, peak_freqs = scan_channels(iq, SAMPLE_RATE)

    if len(peak_freqs) < 2:
        print("[!] Too few peaks — check if file is wideband or narrowband")
        # Fall back to single-channel narrowband demod
        print("[*] Trying narrowband single-channel demod...")
        baud = 9600  # common default
        bits = fm_demod(iq, SAMPLE_RATE, baud)
        for lsb in [False, True]:
            bs = bits2bytes(bits, lsb)
            pkts = find_packets(bs)
            if pkts:
                print(f"[+] Found {len(pkts)} packets!")
                process_packets(pkts); return
        print("    No luck. Check baud rate.")
        return

    # ---- 2. Estimate channel plan ----
    n_channels = len(peak_freqs)
    channel_bw = SAMPLE_RATE / n_channels * 0.8  # 80% of slot width
    print(f"\n[*] Estimated {n_channels} channels, BW per channel ~{channel_bw/1e3:.1f} kHz")

    # ---- 3. Detect dwell time ----
    dwell_samples = detect_dwell(iq, SAMPLE_RATE, peak_freqs[0], channel_bw)
    if dwell_samples is None:
        # Guess: 10 seconds / n_packets; assume ~1000 packets
        dwell_samples = int(SAMPLE_RATE * CAPTURE_SECS / 1000)
        print(f"[*] Guessing dwell: {dwell_samples} samples = "
              f"{dwell_samples/SAMPLE_RATE*1000:.1f} ms")

    n_hops = len(iq) // dwell_samples
    print(f"[*] Total hop slots: {n_hops}")

    # ---- 4. LFSR sequence → channel map ----
    # Try several seeds (most likely seed=1 or a fixed known value)
    for seed in [1, 0xABCDEF, 0xFFFFFF, 0x123456]:
        lfsr_states = lfsr_seq(seed, n_hops)
        channel_indices = [s % n_channels for s in lfsr_states]

        # ---- 5. Per-hop demodulation + packet collection ----
        print(f"\n[*] Demodulating {n_hops} hops (LFSR seed=0x{seed:06X})...")
        baud = 9600  # start with common value; auto-refine below

        all_pkts = []
        bit_stream = []

        for hop_i in range(min(n_hops, 2000)):  # cap at 2000 hops
            ch_idx   = channel_indices[hop_i]
            if ch_idx >= len(peak_freqs): continue
            center   = peak_freqs[ch_idx]
            
            seg = iq[hop_i*dwell_samples:(hop_i+1)*dwell_samples]
            if len(seg) < 64: continue
            
            # Mix down to baseband
            bb = mix_and_filter(seg, center, channel_bw, SAMPLE_RATE)
            
            # Demod
            bits = fm_demod(bb, SAMPLE_RATE, baud)
            bit_stream.extend(bits)
        
        # Try to find packets in the combined bit stream
        for lsb in [False, True]:
            bs = bits2bytes(np.array(bit_stream, dtype=np.uint8), lsb)
            pkts = find_packets(bs)
            if pkts:
                print(f"[+] FOUND {len(pkts)} packets! (seed=0x{seed:06X}, lsb={lsb})")
                process_packets(pkts)
                return
        
        print(f"    seed=0x{seed:06X}: no packets found in {len(bit_stream)//8} bytes")

    # ---- 6. Brute-force baud rates ----
    print("\n[*] Trying multiple baud rates on channel 0...")
    seg = iq[:dwell_samples * 10]  # first 10 hops
    for baud in [1200, 2400, 4800, 9600, 19200, 38400, 115200]:
        bits = fm_demod(seg, SAMPLE_RATE, baud)
        for lsb in [False, True]:
            bs = bits2bytes(bits, lsb)
            pkts = find_packets(bs)
            if pkts:
                print(f"[+] FOUND {len(pkts)} packets at baud={baud}!")
                process_packets(pkts); return
        print(f"    baud={baud}: no packets")

    print("\n[!] Could not decode. Manual steps:")
    print("    1. Open in inspectrum: inspectrum -r 2400000 capture.cf2")
    print("    2. Look for clear modulation pattern")
    print("    3. Find symbol rate from eye diagram")
    print("    4. Edit baud= in this script")

# ---------------------------------------------------------------------------
def process_packets(packets):
    from collections import Counter
    from Crypto.Cipher import ChaCha20

    tc = Counter(p['type'] for p in packets)
    print(f"    Types: {dict(tc)}")
    packets.sort(key=lambda p: p['seq'])

    print("    Sample packets:")
    for p in packets[:8]:
        pl = p['payload']
        ap = ''.join(chr(b) if 32 <= b < 127 else '.' for b in pl[:32])
        print(f"      SEQ={p['seq']:3d} TYPE={p['type']} LEN={p['length']:4d} | "
              f"{pl[:16].hex()} | {ap}")

    main_t = tc.most_common(1)[0][0]
    key_pkts = {p['type']: p['payload'] for p in packets if p['type'] != main_t}
    for t, pl in key_pkts.items():
        print(f"    KEY PKT type={t}: {pl.hex()} | {pl!r}")

    blob = b''.join(p['payload'] for p in sorted(
        [p for p in packets if p['type'] == main_t], key=lambda p: p['seq']))
    print(f"    Assembled {len(blob):,} payload bytes")

    # Save raw
    with open('assembled.bin', 'wb') as f: f.write(blob)

    # Decrypt attempts
    candidates = [(b'\x00'*32, b'\x00'*8, "null")]
    for t, km in key_pkts.items():
        key = (km + b'\x00'*32)[:32]
        for nlen, nl in [(8, '8'), (12, '12')]:
            n = (km[32:] + b'\x00'*nlen)[:nlen] if len(km) >= 32 else b'\x00'*nlen
            candidates.append((key, n, f"t{t}-n{nl}"))
        if len(km) >= 40:
            candidates.append((km[:32], km[32:40], f"t{t}-split8"))
        if len(km) >= 44:
            candidates.append((km[:32], km[32:44], f"t{t}-split12"))

    print("\n    ChaCha20 attempts:")
    for key, nonce, desc in candidates:
        try:
            pt = ChaCha20.new(key=key, nonce=nonce).decrypt(blob[:512])
            preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in pt[:60])
            print(f"      [{desc}] {preview}")
            for mk in [b'RS{', b'RITSEC{', b'flag{']:
                if mk in pt:
                    e = pt.find(b'}', pt.find(mk))
                    print(f"\n  *** FLAG: {pt[pt.find(mk):e+1].decode()} ***\n")
        except Exception as e:
            print(f"      [{desc}] err: {e}")

if __name__ == '__main__':
    main()
