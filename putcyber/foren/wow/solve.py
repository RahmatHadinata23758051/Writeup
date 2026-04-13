#!/usr/bin/env python3
import cv2
import sys

img_path = "flag_qr.png"
img = cv2.imread(img_path)
if img is None:
    print(f"error: cannot read {img_path}")
    sys.exit(1)

detector = cv2.QRCodeDetector()
data, _, _ = detector.detectAndDecode(img)
if not data:
    print("error: QR decode failed")
    sys.exit(1)

print(data)
