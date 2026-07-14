import zipfile
import io
from PIL import Image

def solve():
    with zipfile.ZipFile("chall", "r") as z:
        kpp_data = z.read("paintoppresets/Brush 99.kpp")
    
    im = Image.open(io.BytesIO(kpp_data))
    preset_xml = im.info.get('preset', '')
    
    idx = preset_xml.find("bronco{")
    if idx != -1:
        end = preset_xml.find("}", idx)
        flag = preset_xml[idx:end+1]
        print(f"FLAG: {flag}")
    else:
        print("Flag not found")

if __name__ == "__main__":
    solve()
