import pandas as pd
import matplotlib.pyplot as plt

# Load the data
df = pd.read_csv('trackpad_deltas.csv')

# Initialize coordinates
x, y = 0, 0
paths = []
current_path = []

for index, row in df.iterrows():
    dx, dy, pen_down = row['dx'], row['dy'], row['pen_down']
    
    new_x = x + dx
    new_y = y + dy
    
    if pen_down == 1:
        if not current_path:
            # Start a new path from the current position
            current_path.append((x, y))
        current_path.append((new_x, new_y))
    else:
        if current_path:
            paths.append(current_path)
            current_path = []
            
    x, y = new_x, new_y

# Add the last path if it exists
if current_path:
    paths.append(current_path)

# Collect all pen-down points for ASCII
all_points = []
for path in paths:
    all_points.extend(path)

if all_points:
    min_x = min(p[0] for p in all_points)
    max_x = max(p[0] for p in all_points)
    min_y = min(p[1] for p in all_points)
    max_y = max(p[1] for p in all_points)

    width = 100
    height = 40
    
    grid = [[' ' for _ in range(width + 1)] for _ in range(height + 1)]
    
    for x_p, y_p in all_points:
        ix = int((x_p - min_x) / (max_x - min_x) * width) if max_x != min_x else 0
        iy = int((y_p - min_y) / (max_y - min_y) * height) if max_y != min_y else 0
        # Invert iy because terminal lines go down
        grid[height - iy][ix] = '#'
        
    for row in grid:
        print("".join(row))

# Plotting
plt.figure(figsize=(12, 6))
for path in paths:
    px, py = zip(*path)
    plt.plot(px, py, color='black')

plt.gca().set_aspect('equal', adjustable='box')
plt.axis('off')
plt.savefig('flag.png')
print("Flag saved to flag.png")
