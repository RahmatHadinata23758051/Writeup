#!/usr/bin/env python3
import io
import zipfile
from pathlib import Path

IMAGE_PATH = Path('ghost.jpg')
ZIP_OFFSET = 120_948
PASSWORD = b'phantom'
TARGET_FILE = 'flag.txt'


def main() -> None:
    data = IMAGE_PATH.read_bytes()
    zip_data = data[ZIP_OFFSET:]

    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        flag = zf.read(TARGET_FILE, pwd=PASSWORD).decode().strip()

    print(flag)


if __name__ == '__main__':
    main()
