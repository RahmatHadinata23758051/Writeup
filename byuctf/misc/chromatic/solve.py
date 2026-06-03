import cv2

def solve():
    cap = cv2.VideoCapture('chromatic.mp4')
    
    flag_chars = []
    last_r = None
    
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break
            
        # Ambil nilai R dari piksel tengah (OpenCV menggunakan format BGR)
        b, g, r = frame[100, 100]
        
        # Jika nilai R berubah dari frame sebelumnya, catat nilai barunya
        if r != last_r:
            flag_chars.append(chr(r))
            last_r = r
            
    cap.release()
    
    # Gabungkan semua karakter unik yang ditemukan
    flag = "".join(flag_chars)
    print(f"\nResult: {flag}\n")

if __name__ == "__main__":
    solve()
