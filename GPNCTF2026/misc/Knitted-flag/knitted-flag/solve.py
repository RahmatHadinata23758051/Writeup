
import re
from PIL import Image

def parse_knitout(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()

    data = [] # List of (needle_type, needle_idx, carrier, row)
    row_num = 0
    last_direction = None
    
    current_carrier = None
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith(';'):
            continue
            
        parts = line.split()
        cmd = parts[0]
        
        if cmd in ['knit', 'tuck']:
            # knit/tuck [direction] [needle] [carrier]
            if len(parts) < 3:
                continue
                
            direction = parts[1]
            needle = parts[2]
            
            carrier = current_carrier
            if len(parts) >= 4:
                try:
                    carrier = int(parts[3])
                    current_carrier = carrier
                except ValueError:
                    pass
            
            if carrier is None:
                continue

            if last_direction is not None and direction != last_direction:
                row_num += 1
            
            last_direction = direction
            
            n_type = needle[0] # 'f' or 'b'
            try:
                n_idx = int(needle[1:])
            except ValueError:
                continue
            
            data.append((n_type, n_idx, carrier, row_num))
            
    return data

def visualize(data):
    if not data:
        return
    
    max_row = max(d[3] for d in data)
    max_needle = max(d[1] for d in data)
    
    # carriers 1-5 are used
    carriers = [1, 2, 3, 4, 5]
    
    # Create a long horizontal strip: Width = rows, Height = needles
    # Let's create one for each carrier
    for c in carriers:
        img = Image.new('RGB', (max_row + 1, max_needle + 1), (0, 0, 0))
        for n_type, n_idx, carrier, row in data:
            if carrier == c:
                img.putpixel((row, n_idx), (255, 255, 255)) # White on black
        
        # Scale it vertically so it's easier to read
        # Height is only ~20, let's make it 100
        img = img.resize((max_row + 1, (max_needle + 1) * 5), Image.NEAREST)
        img.save(f'carrier_{c}.png')
        print(f"Saved carrier_{c}.png")

    # Also combined carriers
    img_all = Image.new('RGB', (max_row + 1, (max_needle + 1) * 5), (0, 0, 0))
    colors = {
        1: (255, 0, 0),
        2: (0, 255, 0),
        3: (0, 0, 255),
        4: (255, 255, 0),
        5: (255, 0, 255),
    }
    
    for n_type, n_idx, carrier, row in data:
        color = colors.get(carrier, (255, 255, 255))
        # Draw a 5x1 block for visibility
        for offset in range(5):
            img_all.putpixel((row, n_idx * 5 + offset), color)
    
    img_all.save('all_carriers_rotated.png')
    print("Saved all_carriers_rotated.png")

if __name__ == "__main__":
    data = parse_knitout('/home/nata/ctf/GPNCTF2026/misc/Knitted-flag/knitted-flag/pattern.k')
    visualize(data)
