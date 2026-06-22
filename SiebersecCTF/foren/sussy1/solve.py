import matplotlib.pyplot as plt
import re

def parse_gcode(filename):
    x, y = 0, 0
    z = 0
    lines = []
    
    with open(filename, 'r') as f:
        for line in f:
            if line.startswith('G1'):
                parts = line.split()
                new_x = x
                new_y = y
                extruding = False
                
                for part in parts:
                    if part.startswith('X'):
                        new_x = float(part[1:])
                    elif part.startswith('Y'):
                        new_y = float(part[1:])
                    elif part.startswith('Z'):
                        z = float(part[1:])
                    elif part.startswith('E'):
                        extruding = True
                
                # Only plot the first layer
                if extruding and z == 0.35:
                    lines.append(((x, y), (new_x, new_y)))
                
                x, y = new_x, new_y
            elif line.startswith('G0'):
                parts = line.split()
                for part in parts:
                    if part.startswith('X'):
                        x = float(part[1:])
                    elif part.startswith('Y'):
                        y = float(part[1:])
                    elif part.startswith('Z'):
                        z = float(part[1:])
    return lines

lines = parse_gcode('sussy')

plt.figure(figsize=(12, 8))
for start, end in lines:
    plt.plot([start[0], end[0]], [start[1], end[1]], 'b-', linewidth=0.5)

plt.axis('equal')
plt.savefig('plot.png')
print("Plot saved to plot.png")
