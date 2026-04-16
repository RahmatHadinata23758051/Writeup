from PIL import Image, ImageChops
img1 = Image.open('_Temoc_keyring.png.extracted/key/Temoc_keyring(orig).png')
img2 = Image.open('_Temoc_keyring.png.extracted/key/where_are_my_keys.png')
diff = ImageChops.difference(img1, img2)
diff_enhanced = diff.point(lambda x: 255 if x > 0 else 0)
diff_enhanced.save('diff.png')
print('Non-zero pixels:', sum(1 for p in diff.getdata() if any(c > 0 for c in p)))
