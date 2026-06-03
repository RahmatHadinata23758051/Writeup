# Alright. Time Paradox Writeup

## Analisis Awal
Diberikan sebuah file PCAP bernama `chall.pcapng` dan deskripsi yang memberikan petunjuk "What protocol is associated with time?". Protokol yang paling sering dikaitkan dengan waktu dalam jaringan adalah Network Time Protocol (NTP).

## Investigasi Jaringan (Network Forensics)
1. **Filtering Trafik NTP:**
   Menggunakan `tshark` atau Wireshark, filter diterapkan untuk hanya menampilkan paket yang menggunakan protokol NTP:
   ```bash
   tshark -r chall.pcapng -Y "ntp"
   ```
   Terdapat beberapa paket NTP yang dikirimkan dari alamat `192.168.132.1` ke `192.168.132.133`.

2. **Analisis Payload:**
   Karena NTP mengirimkan timestamp, data tersebut mungkin dimodifikasi untuk menyembunyikan informasi. Payload UDP dari paket-paket NTP tersebut diekstrak untuk dianalisis lebih lanjut:
   ```bash
   tshark -r chall.pcapng -Y "ntp" -T fields -e udp.payload
   ```

   Hasil ekstraksi payload UDP dari paket pertama menunjukkan pola hexadecimal seperti berikut:
   `23020a0000000000000000007f0000016553f162000000006553f179000000006553f175000000006553f16300000000`

   Dapat dilihat bahwa pada bagian akhir payload (area yang biasanya digunakan untuk transmit/receive timestamps pada NTP), terdapat pola yang berulang: `6553f1XX00000000`.

3. **Ekstraksi Flag:**
   Byte `XX` pada pola tersebut berubah pada setiap blok. Jika dikonversi dari Hexadecimal ke ASCII, kita akan mendapatkan:
   - `62` -> 'b'
   - `79` -> 'y'
   - `75` -> 'u'
   - `63` -> 'c'

   Pola ini menunjukkan karakter pembuka format flag yaitu `byuc`.

   Untuk mengekstrak seluruh flag, dilakukan pembacaan dari setiap blok berulang dalam paket-paket NTP. Total ada 10 paket NTP yang masing-masing membawa 4 karakter tersembunyi (pada paket terakhir hanya 1 karakter yang valid, sisanya null byte/`00`).

## Solusi (Automasi Script)
Dibuat sebuah script `solve.py` menggunakan Python untuk mengotomatisasi ekstraksi paket NTP dan melakukan parsing terhadap karakter yang disembunyikan tersebut.

```python
import subprocess

def main():
    cmd = ['tshark', '-r', 'chall.pcapng', '-Y', 'ntp', '-T', 'fields', '-e', 'udp.payload']
    output = subprocess.check_output(cmd).decode('utf-8').splitlines()
    flag = ""
    for line in output:
        payload = line.strip()
        if not payload:
            continue
        parts = payload.split("6553f1")
        for part in parts[1:]:
            byte_hex = part[:2]
            if byte_hex != "00":
                flag += chr(int(byte_hex, 16))
    print(flag)

if __name__ == '__main__':
    main()
```

## Hasil
Setelah menggabungkan semua karakter dari pola payload tersebut, didapatkan string flag penuh.

**Flag:** `byuctf{S0_My_P4r4d0x_!d34_D!dnt_W0rk}`