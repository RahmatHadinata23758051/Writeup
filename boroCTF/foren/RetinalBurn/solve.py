#!/usr/bin/env python3
from pathlib import Path
from PIL import Image
import numpy as np

ROOT = Path(__file__).resolve().parent
INFILE = ROOT / "burn.png"
OUTFILE = ROOT / "extracted_blue_flag.png"

img = Image.open(INFILE).convert("RGB")
arr = np.asarray(img).astype(np.int16)

# The image is intentionally almost-white.  Hidden text is encoded by lowering
# one color channel by a tiny amount.  For the real flag, the blue channel is the
# one that changes, so compare blue-difference against red/green-difference.
diff = 255 - arr
blue_specific = diff[:, :, 2] - np.maximum(diff[:, :, 0], diff[:, :, 1])
mask = (blue_specific > 0).astype(np.uint8) * 255

# Crop the top band where the chromatic text lives and enlarge it for reading.
crop = Image.fromarray(mask, "L").crop((0, 40, 800, 130))
crop = crop.resize((1600, 180), Image.Resampling.NEAREST)
crop.save(OUTFILE)

# The extraction image reads: boroCTF{OW_MY_EYES!}
print("boroCTF{OW_MY_EYES!}")
print(f"proof image written to: {OUTFILE.name}")
