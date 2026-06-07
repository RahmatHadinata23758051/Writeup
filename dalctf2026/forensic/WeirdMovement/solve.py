import matplotlib.pyplot as plt

def to_signed(n):
    return n - 256 if n > 127 else n

x, y = 0, 0
xs, ys = [], []
xs_pressed, ys_pressed = [], []

with open('mouse_data.txt', 'r') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        # Support both '00:ff:ff:00' and '00ffff00' formats
        if ':' in line:
            data = [int(b, 16) for b in line.split(':')]
        else:
            data = [int(line[i:i+2], 16) for i in range(0, len(line), 2)]
        
        if len(data) < 3:
            continue
            
        btn = data[0]
        dx = to_signed(data[1])
        dy = to_signed(data[2])
        
        x += dx
        y -= dy # y is usually inverted in screen coordinates
        
        xs.append(x)
        ys.append(y)
        
        if btn & 0x01: # Left button pressed
            xs_pressed.append(x)
            ys_pressed.append(y)

plt.figure(figsize=(10, 10))
plt.scatter(xs, ys, s=1, c='gray', alpha=0.3, label='Movement')
if xs_pressed:
    plt.scatter(xs_pressed, ys_pressed, s=1, c='red', label='Left Click')
plt.legend()
plt.axis('equal')
plt.savefig('plot.png')
print("Plot saved to plot.png")
