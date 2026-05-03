# Writeup - Ratte (Forensics)

## Challenge Description
You are an incident response specialist. Your company received a network traffic dump (pcap file) intercepted from one of the corporate network segments during suspicious activity. Analyze what's wrong here.

## Analysis
Upon analyzing the `Ratte.pcap` file, several anomalies were found:
1. The protocol hierarchy showed a mix of HTTP, FTP, SSH, and DNS traffic, but most of it appeared to be background noise with very small packets and no complete handshakes.
2. A specific TCP session on port **1337** stood out. It consisted of 21 packets, all having the same sequence number (`Seq=1`). Wireshark/tshark flagged these as "TCP Retransmissions," but they contained different payloads.
3. The first packet on port 1337 had the payload `deadbeef42`. This acted as a "beacon" or key.
4. Subsequent packets started with `0xCC` and had 4 or 3 additional bytes of data.

## Exploitation / Decoding
By analyzing the payloads of the port 1337 packets, it was discovered that the flag was hidden in the bytes at indices 3 and 4 of each packet, XORed with the last byte of the first beacon packet (`0x42`).

### Decoding Table:
- P1: `deadbeef42` (Key byte: `0x42`)
- P2: `cc 53 02 09 37` -> `0x09^0x42=K`, `0x37^0x42=u`
- P3: `cc b9 02 20 11` -> `0x20^0x42=b`, `0x11^0x42=S`
- P4: `cc 75 02 16 17` -> `0x16^0x42=T`, `0x17^0x42=U`
- P5: `cc cb 02 39 2c` -> `0x39^0x42={`, `0x2c^0x42=n`
- ...
- P21: `cc 1e 01 3f` -> `0x3f^0x42=}`

The complete flag is constructed by concatenating these XORed characters.

### Solve Script
```python
key_byte = 0x42
packets = [
    'cc53020937', 'ccb9022011', 'cc75021617', 'cccb02392c', 'ccb102721d',
    'cc61022f72', 'cc8e023071', 'cc00021d25', 'ccc8023071', 'cc40023232',
    'cc6502732c', 'cc3b02251d', 'ccda02732c', 'cc2a021d36', 'cc45022a71',
    'cc21021d26', 'cc45027630', 'cc2602291d', 'cc3f023470', 'cc1e013f'
]
data = []
for p in packets:
    b = bytes.fromhex(p)
    data.extend(b[3:])
flag = "".join(chr(x ^ key_byte) for x in data)
print(flag)
```

## Flag
`KubSTU{n0_m0r3_gr3pp1ng_1n_th3_d4rk_v2}`
