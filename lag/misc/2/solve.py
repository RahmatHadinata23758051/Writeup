import socket
import re

def has_double_char(word):
    for i in range(len(word) - 1):
        if word[i] == word[i+1]:
            return True
    return False

def solve():
    host = "chall1.lagncra.sh"
    port = 18376

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    
    # Penyangga untuk menampung data yang masuk
    buffer = ""

    try:
        while True:
            chunk = s.recv(4096).decode('utf-8')
            if not chunk:
                break
            
            buffer += chunk
            print(chunk, end="")

            # Cari pola "Aufgabe X: kata1 kata2 ..."
            # Kita cari baris yang mengandung "Aufgabe" diikuti angka dan ":"
            matches = re.findall(r"Aufgabe \d+:\s*(.*)", buffer)
            
            if matches:
                # Ambil baris soal paling terakhir dari buffer
                current_task_line = matches[-1].strip()
                
                # Pastikan ini bukan bagian dari "Beispiel"
                if "Beispiel" in buffer:
                    # Hapus tanda contoh dari buffer agar tidak terproses ulang
                    buffer = buffer.replace("Beispiel", "DONE")

                words = current_task_line.split()
                answer = ""
                
                for word in words:
                    clean_word = word.strip(".,!?:")
                    if has_double_char(clean_word):
                        answer = clean_word
                        break
                
                if answer:
                    print(f"\n[+] Sending: {answer}")
                    s.sendall((answer + "\n").encode('utf-8'))
                    # Kosongkan buffer soal agar tidak menjawab soal yang sama dua kali
                    buffer = ""

            if "LNC26{" in chunk:
                print("\n\nFLAG DITEMUKAN!")
                break

    except Exception as e:
        print(f"\nError: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    solve()
