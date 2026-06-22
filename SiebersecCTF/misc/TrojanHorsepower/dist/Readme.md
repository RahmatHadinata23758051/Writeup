# Trojan Horsepower - Writeup

## Analysis
The challenge provides a text classification service that uses an ONNX model to categorize documents. The goal is to trigger the `APPROVED_STABLE_SECRET` class with a confidence of at least 0.999.

### Initial Reconnaissance
- `server.py` reveals a preprocessing pipeline: normalization, leetspeak replacement, horse synonym replacement, and sentence shuffling.
- The model is a very small ONNX file (2.6KB).
- Probing the model behaviorally shows it mostly behaves like a Bag of Words (BoW) model for common classes.
- However, the `APPROVED_STABLE_SECRET` class seems to have no single-token triggers.

### Deep Dive into the Model
By inspecting the ONNX model's structure (using `strings` and direct protobuf parsing), we discovered a "Trojan" mechanism:
1. The model slices the first 8 tokens of the input.
2. It compares this slice to a target sequence of 8 integers using an `Equal` operation.
3. It uses `ReduceProd` to ensure ALL 8 tokens match exactly.
4. If they match, it adds a large value (`80.0`) to the secret class logit.
5. Any non-PAD tokens beyond the first 8 positions incur a heavy "tail penalty," subtracting from the secret class logit.

### Finding the Trigger
We scanned the `model.onnx` binary for sequences of 8-byte integers (64-bit) that fall within the vocabulary range. At offset 976, we found the sequence: `(6, 25, 7, 54, 9, 10, 28, 8)`.

Mapping these IDs back to tokens using `tokenizer.json`:
- 6: `oats`
- 25: `invoice`
- 7: `bridle`
- 54: `mango`
- 9: `pasture`
- 10: `hoof`
- 28: `delta`
- 8: `saddle`

The trigger phrase is: `oats invoice bridle mango pasture hoof delta saddle`.

## Exploitation
Submitting this exact 8-token phrase to the service triggers the secret class with 1.0 confidence, revealing the flag.

## Flag
`sctf{tokenizers_are_part_of_the_attack_surface}`
