#!/usr/bin/env python3
from pathlib import Path

import h5py
import numpy as np


MODEL_NAME = "model.h5?token=eyJ1c2VyX2lkIjoyMjEsInRlYW1faWQiOjEzOCwiZmlsZV9pZCI6MTF9.acbJpQ.87zTywivX__uS0hafo6NRAabdkg"
DATASET_PATH = "model_weights/secret_layer/sequential/secret_layer/kernel"


def main() -> None:
    model_path = Path(__file__).with_name(MODEL_NAME)

    with h5py.File(model_path, "r") as handle:
        kernel = handle[DATASET_PATH][()]

    for row in kernel:
        chars = np.rint(row * 1000).astype(int)
        if np.all((32 <= chars) & (chars < 127)):
            candidate = "".join(map(chr, chars))
            if candidate.startswith("texsaw{") and candidate.endswith("}"):
                print(candidate)
                return

    raise SystemExit("flag not found")


if __name__ == "__main__":
    main()
