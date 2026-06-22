from PIL import Image

def solve():
    img = Image.open('chall.png')
    pixels = img.load()
    
    # The image is 400x300, divided into 100x100 blocks
    # We read row-major order
    flag = ""
    for y in range(0, 300, 100):
        for x in range(0, 400, 100):
            r, g, b = pixels[x, y]
            if (r, g, b) == (0, 0, 0):
                continue
            
            # Convert RGB to characters
            flag += chr(r)
            if g != 0:
                flag += chr(g)
            if b != 0:
                flag += chr(b)
            
            if '}' in flag:
                print(flag)
                return

if __name__ == "__main__":
    solve()
