# Blackwall Protocol - Forensics Writeup

## Analysis
The challenge provides a PCAP file `david_last_moments.bd` and a Python script `bd_tuner.py`. 
Upon examining `bd_tuner.py`, a comment hints at a "network timing covert channel" with specific delays: `0.15` and `0.65`.

```python
# The stuttering here hints at the network timing covert channel
for i in range(1, 6):
    delay = random.choice([0.15, 0.65]) # Matches our timing channel delays!
    console.print(f"[bold blue]>>> SANDEVISTAN ACTIVATION: {i*20}% ...[/bold blue]")
    time.sleep(delay)
```

Inspecting the PCAP file with `tshark`, we observe that the inter-packet arrival times (delta times) between consecutive UDP packets are consistently around `0.00015s` and `0.00065s`. These correspond directly to the values in the script.

## Solution
1. **Extract Delta Times**: Use `tshark` to extract the `frame.time_delta` for the UDP stream.
2. **Decode Bits**: 
   - A delta of `~0.00015s` represents a `0` bit.
   - A delta of `~0.00065s` represents a `1` bit.
3. **Convert to ASCII**: Group the bits into bytes and convert them to characters.

The extracted bits (starting from the first delta) form the flag.

### Solve Script
```python
def decode_deltas(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
    
    bits = ""
    for line in lines:
        val = float(line.strip())
        if val == 0: continue # Skip first packet
        if val < 0.0004:
            bits += "0"
        else:
            bits += "1"
    
    flag = ""
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) == 8:
            flag += chr(int(byte, 2))
    print(flag)
```

## Flag
`boroCTF{s4nd3v1st4n_gh0st_1n_th3_m4ch1n3_8f92a}`
