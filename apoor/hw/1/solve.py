import struct
import matplotlib.pyplot as plt

def solve():
    with open('controler_fw.bin', 'rb') as f:
        content = f.read()

    # Cari data setelah JBUFHDR5SEG4
    header = b'JBUFHDR5SEG4'
    start = content.find(header)
    if start == -1: return
    
    # Ambil data murni (3984 byte = 332 titik)
    raw_data = content[start+17 : start+17+3984]
    
    # 1. Parsing Floats
    pts = []
    for i in range(0, len(raw_data)-11, 12):
        pts.append(struct.unpack('<fff', raw_data[i:i+12]))

    # 2. Fungsi Plotting
    def plot_data(mode='abs'):
        plt.figure(figsize=(12, 4))
        cur_x, cur_y, cur_z = 0, 0, 0
        
        # Simpan dalam stroke (coretan terpisah)
        strokes = []
        stroke_x, stroke_y = [], []
        
        for dx, dy, dz in pts:
            if mode == 'rel':
                cur_x += dx; cur_y += dy; cur_z += dz
            else:
                cur_x, cur_y, cur_z = dx, dy, dz
            
            # Filter angka absurd (misal > 1000 atau NaN)
            if abs(cur_x) > 1000 or abs(cur_y) > 1000: continue
            
            # Logika Pahat: Jika Z negatif, berarti mengukir (Draw)
            if cur_z < -1.0:
                stroke_x.append(cur_x)
                stroke_y.append(cur_y)
            else:
                if stroke_x:
                    strokes.append((stroke_x, stroke_y))
                    stroke_x, stroke_y = [], []
        
        if stroke_x: strokes.append((stroke_x, stroke_y))
        
        for sx, sy in strokes:
            plt.plot(sx, sy, color='black', linewidth=1)
        
        plt.gca().set_aspect('equal')
        plt.title(f"Mode: {mode.upper()}")
        plt.savefig(f'flag_{mode}.png')
        print(f"File flag_{mode}.png dibuat.")

    plot_data('abs')
    plot_data('rel')

solve()
