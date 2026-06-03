# heapshifter

> The heap remembers what you shift into it. Allocate big, free freely, and
> remember: nothing you write is stored the way you typed it..

`nc <host> 36970`

## Files
- `heapshifter`              — chall binary
- `libc.so.6`               — remote libc
- `ld-linux-x86-64.so.2`    — remote loader
- `Dockerfile` / `docker-compose.yml` — host locally lol

## run locally
```sh
# match the remote libc/loader
patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . heapshifter
./heapshifter

# or reproduce the exact service
docker compose up --build      # listens on :36970
```
