#!/usr/bin/env python3.10

import importlib.machinery
import importlib.util
import pickle
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def load_payload():
    loader = importlib.machinery.SourcelessFileLoader("payload", str(ROOT / "payload.pyc"))
    spec = importlib.util.spec_from_loader("payload", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    sys.modules["payload"] = module
    return module


def main():
    if sys.version_info[:2] != (3, 10):
        raise SystemExit("Run this with python3.10 because payload.pyc targets CPython 3.10.")

    load_payload()
    with open(ROOT / "model.pkl", "rb") as fh:
        model = pickle.load(fh)

    history = ["snow", "candle", "tangerine", "clock"]
    result = model.infer("example", history)
    print(result["ticket"])
    print(result["ticket"].encode("ascii"))
    print(__import__("base64").b85decode(result["ticket"]).decode())


if __name__ == "__main__":
    main()
