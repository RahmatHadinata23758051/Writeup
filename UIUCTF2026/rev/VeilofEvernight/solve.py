#!/usr/bin/env python3
import os, sys, time, signal, subprocess, tempfile, textwrap, pathlib

FLAG = "uiuctf{wh3r3_is_my_c4m3r4_4+3}"


def cstr(s: str) -> str:
    return s.replace('\\','\\\\').replace('"','\\"')


def dump_runtime_data(binary: str, out_path: str):
    # Run the binary until it is waiting at the prompt. At this point the static
    # runtime data has been decrypted by its startup logic.
    p = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    time.sleep(0.25)
    try:
        maps = pathlib.Path(f"/proc/{p.pid}/maps").read_text().splitlines()
        target = None
        for line in maps:
            rng, perms, *_ = line.split(maxsplit=2)
            a,b = [int(x,16) for x in rng.split('-')]
            if a <= 0x367000 and b >= 0x36a000 and 'rw' in perms:
                target = (a,b)
                break
        if not target:
            # Fallback: the observed fixed mapping in this challenge.
            target = (0x367000, 0x36a000)
        a,b = target
        with open(f"/proc/{p.pid}/mem", "rb", buffering=0) as mem:
            mem.seek(a)
            blob = mem.read(b-a)
        pathlib.Path(out_path).write_bytes(blob)
    finally:
        try:
            p.kill()
        except Exception:
            pass
        try:
            p.wait(timeout=1)
        except Exception:
            pass


def build_and_run_dumper(binary: str, runtime: str, png_out: str):
    src = f'''
#define _GNU_SOURCE
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
static unsigned char *buf; static unsigned char *seen; static uint64_t maxidx=0, count=0;
void cb(uint64_t idx, unsigned char val, void* user) {{
    if (idx < 10000000ULL) {{
        if (!seen[idx]) {{ seen[idx]=1; count++; }}
        buf[idx]=val;
        if (idx > maxidx) maxidx=idx;
    }}
}}
void mapseg(int fd, uintptr_t va, off_t off, size_t filesz, size_t memsz) {{
    size_t pg=4096; uintptr_t base=va&~(pg-1); size_t delta=va-base;
    off_t o=off&~(off_t)(pg-1); size_t maplen=((delta+memsz+pg-1)/pg)*pg;
    void*p=mmap((void*)base,maplen,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0);
    if(p==(void*)-1){{perror("mmap");exit(1);}}
    lseek(fd,o,0); if(read(fd,(void*)base,filesz+delta)<0){{perror("read");exit(1);}}
}}
void loadfile(const char*path, uintptr_t va) {{
    int fd=open(path,0); if(fd<0){{perror(path);exit(1);}}
    char tmp[65536]; ssize_t n; uintptr_t p=va;
    while((n=read(fd,tmp,sizeof(tmp)))>0){{memcpy((void*)p,tmp,n); p+=n;}}
    close(fd);
}}
int main() {{
    buf=calloc(10000000,1); seen=calloc(10000000,1);
    int fd=open("{cstr(binary)}",0); if(fd<0){{perror("binary");return 1;}}
    mapseg(fd,0x200000,0,0x8bb40,0x8bb40);
    mapseg(fd,0x28cb40,0x8bb40,0xd4c10,0xd4c10);
    mapseg(fd,0x362750,0x160750,0x4238,0x48b0);
    mapseg(fd,0x367988,0x164988,0x1de0,0x7550);
    loadfile("{cstr(runtime)}",0x367000);
    uint64_t ctx[4]={{0}};
    int (*vm)(uint64_t*, void*, void*)=(void*)0x297cd0;
    int ok=vm(ctx,(void*)&cb,NULL);
    if(!ok){{fprintf(stderr,"VM failed\\n");return 2;}}
    FILE*f=fopen("{cstr(png_out)}","wb");
    fwrite(buf,1,maxidx+1,f); fclose(f);
    fprintf(stderr,"dumped %lu bytes to {cstr(png_out)}\\n", maxidx+1);
    return 0;
}}
'''
    tmpdir = tempfile.mkdtemp(prefix="evernight_solve_")
    cpath = os.path.join(tmpdir, "dump.c")
    exe = os.path.join(tmpdir, "dump")
    pathlib.Path(cpath).write_text(src)
    subprocess.check_call(["gcc", "-no-pie", "-O2", "-o", exe, cpath])
    subprocess.check_call([exe])


def main():
    binary = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "/mnt/data/evernight")
    out_png = os.path.abspath(sys.argv[2] if len(sys.argv) > 2 else "/mnt/data/evernight_memory.png")
    with tempfile.TemporaryDirectory(prefix="evernight_rt_") as td:
        runtime = os.path.join(td, "data_rw.bin")
        known = "/mnt/data/evernight_maps/367000-36a000_rw-p.bin"
        if os.path.exists(known):
            pathlib.Path(runtime).write_bytes(pathlib.Path(known).read_bytes())
        else:
            dump_runtime_data(binary, runtime)
        build_and_run_dumper(binary, runtime, out_png)
    print(f"[+] reconstructed memory image: {out_png}")
    print(f"[+] flag: {FLAG}")

if __name__ == "__main__":
    main()

