# Writeup for 1000-7 challenge

The challenge contains a MIDI file `chal.mid` playing the "Unravel" melody from Tokyo Ghoul.

Analyzing the MIDI events in Track 1, we found many `pitchwheel` events that adjust the pitch.
Specifically, there are 752 `pitchwheel` events, which consist of 376 pairs of pitches alternating between `2304` and `-2304`.

Mapping `(2304, -2304)` to `1` and `(-2304, 2304)` to `0` extracts the binary data.
Decoding the binary data yields:
`\xc0\xde*grodno{U1tr@_m3g@_5up3r_Gul_M1d_SF_1000-7}\xc5\x11`

The flag is:
`grodno{U1tr@_m3g@_5up3r_Gul_M1d_SF_1000-7}`
