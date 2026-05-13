CTF Writeup — Nine Strings, Nine Bytes, Nine Nines?

Event: RAM CTF

Category: Crypto

Difficulty: Easy

Flag: RAM{M0rPH063N371C_F131D}

Challenge Description

steelsecure.ai have switched to a new url-safe data transmission method that we don't understand. As always, our insider has access to the api they use to create these url-safe strings, but we are no closer to working out how they work.

Target File: output.txt

Connection: nc 10.42.5.10 9999

Reconnaissance

Step 1 — Analyze Output File

File output.txt berisi tiga baris data dengan format [integer]:[string_angka_panjang].

75:001452364189...
33:008254923251...
24:002055539561...


Angka di depan titik dua sepertinya menunjukkan panjang byte dari pesan asli, sedangkan string angka adalah data yang terenkripsi/terkode.

Step 2 — Interact with the Server

Menghubungkan ke server menggunakan netcat memberikan informasi krusial di banner:

==============================================
State of the art encoding by steelsecure.ai
Commands:
  encode <text>   — encode a string
  decode <text>   — decode a base-999 string (UNDER MAINT!)
==============================================


Banner tersebut secara eksplisit menyebutkan "Base-999 string". Judul tantangan "Nine Strings, Nine Bytes, Nine Nines?" juga mengonfirmasi penggunaan angka 9.

Exploitation

Step 3 — Pattern Analysis

Dalam Base-999, setiap "digit" dari sistem bilangan tersebut bernilai maksimal 998. Karena $999$ mendekati $1000$ ($10^3$), maka cara paling masuk akal untuk merepresentasikan satu digit Base-999 dalam string desimal adalah dengan menggunakan 3 digit angka (000 hingga 998).

Contoh: String 008254...

Digit ke-1: 008 (Nilai: 8)

Digit ke-2: 254 (Nilai: 254)

Step 4 — Mathematical Decoding

Untuk mengembalikan data ke bentuk aslinya, kita harus:

Memecah string menjadi blok sepanjang 3 karakter.

Menghitung nilai total desimal (Big Integer) menggunakan rumus:


$$V = \sum_{i=0}^{n-1} d_i \cdot 999^{(n-1-i)}$$

Mengonversi integer $V$ tersebut kembali menjadi bytes sesuai dengan panjang yang diberikan di awal.

Step 5 — Automated Script

Menggunakan Python untuk melakukan konversi otomatis pada data di output.txt:

def solve_base999(encoded_data, byte_len):
    # Pecah per 3 digit
    chunks = [int(encoded_data[i:i+3]) for i in range(0, len(encoded_data), 3)]
    
    # Konversi Base-999 ke Integer
    val = 0
    for c in chunks:
        val = val * 999 + c
        
    # Konversi Integer ke Bytes
    return val.to_bytes(byte_len, 'big').decode()

# Mengambil salah satu sampel dari output.txt
payload = "001452364189848287923821742568954303648698985244216888407919381357574656595589327310217711904601016561079226903056403550476359808600659903252340182702873643487914166139407119810527154"
print(solve_base999(payload, 75))


Menjalankan script tersebut pada baris pertama menghasilkan flag yang dicari.

Flag

RAM{M0rPH063N371C_F131D}
