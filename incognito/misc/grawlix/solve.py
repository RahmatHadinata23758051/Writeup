#!/usr/bin/env python3
import os
import subprocess
import sys
from pathlib import Path

C_CODE = r'''#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MOD 1000000007u
#define TARGET_OPS 100000000u

static inline uint32_t mod_reduce_u32(uint32_t x) {
    if (x >= MOD) x -= MOD;
    if (x >= MOD) x -= MOD;
    if (x >= MOD) x -= MOD;
    return x;
}

static inline uint32_t step(uint32_t v, unsigned char b, uint32_t *count) {
    switch (b) {
        case '@':
            v += 101u;
            if (v >= MOD) v -= MOD;
            (*count)++;
            break;
        case '#': {
            uint32_t t = v * 3u;
            v = mod_reduce_u32(t);
            (*count)++;
            break;
        }
        case '$':
            v ^= 4242u;
            (*count)++;
            break;
        case '%':
            if (v & 1u) {
                uint32_t t = v * 3u + 1u;
                v = mod_reduce_u32(t);
            } else {
                v >>= 1u;
            }
            (*count)++;
            break;
        case '&':
            v = (~v) & 0xFFFFFu;
            (*count)++;
            break;
        default:
            break;
    }
    return v;
}

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(1339);
    if (inet_pton(AF_INET, "34.131.216.230", &sa.sin_addr) != 1) { perror("inet_pton"); return 1; }
    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) != 0) { perror("connect"); return 1; }

    uint32_t v = 0;
    int have_v = 0;
    int in_stream = 0;
    uint32_t op_count = 0;

    char *hdr = malloc(1<<20);
    if (!hdr) return 1;
    size_t hlen = 0;

    unsigned char *buf = malloc(1<<20);
    if (!buf) return 1;

    while (op_count < TARGET_OPS) {
        ssize_t n = recv(fd, buf, 1<<20, 0);
        if (n <= 0) { fprintf(stderr, "recv end before target (%zd)\n", n); return 1; }

        if (!in_stream) {
            if (hlen + (size_t)n >= (1<<20)) { fprintf(stderr, "header too big\n"); return 1; }
            memcpy(hdr + hlen, buf, (size_t)n);
            hlen += (size_t)n;
            hdr[hlen] = '\0';

            if (!have_v) {
                char *p = strstr(hdr, "Starting Value (V) = ");
                if (p) {
                    p += strlen("Starting Value (V) = ");
                    v = (uint32_t)strtoul(p, NULL, 10);
                    have_v = 1;
                }
            }

            char *m = strstr(hdr, "[INCOMING STREAM]\n");
            if (!m || !have_v) continue;

            in_stream = 1;
            char *ops = m + strlen("[INCOMING STREAM]\n");
            size_t rem = (size_t)(hdr + hlen - ops);
            for (size_t i = 0; i < rem && op_count < TARGET_OPS; i++) {
                v = step(v, (unsigned char)ops[i], &op_count);
            }
            hlen = 0;
        } else {
            for (ssize_t i = 0; i < n && op_count < TARGET_OPS; i++) {
                v = step(v, buf[i], &op_count);
            }
        }
    }

    char ans[64];
    int l = snprintf(ans, sizeof(ans), "%u\n", v);
    send(fd, ans, (size_t)l, 0);

    while (1) {
        ssize_t n = recv(fd, buf, 1<<20, 0);
        if (n <= 0) break;
        fwrite(buf, 1, (size_t)n, stdout);
    }

    close(fd);
    free(buf);
    free(hdr);
    return 0;
}
'''


def main() -> int:
    base = Path(__file__).resolve().parent
    c_path = base / '.solve_fast.c'
    bin_path = base / '.solve_fast_bin'

    c_path.write_text(C_CODE)
    compile_cmd = ['gcc', '-O3', '-march=native', '-pipe', str(c_path), '-o', str(bin_path)]
    try:
        subprocess.run(compile_cmd, check=True)
    except subprocess.CalledProcessError:
        print('[!] gcc compile failed', file=sys.stderr)
        return 1

    try:
        result = subprocess.run([str(bin_path)], check=False)
        return result.returncode
    finally:
        # Keep artifacts for repeatability/debug if needed.
        pass


if __name__ == '__main__':
    raise SystemExit(main())
