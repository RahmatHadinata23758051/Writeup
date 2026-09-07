#!/usr/bin/env python3
from pathlib import Path
import struct
import collections
from collections import deque

try:
    from shapely.geometry import Polygon, box, Point
    from shapely.affinity import affine_transform
    from shapely.strtree import STRtree
except ImportError as e:
    raise SystemExit("Dependency missing: install shapely dulu (python3 -m pip install shapely)") from e

BASE = Path(__file__).resolve().parent
MAG = BASE / "flag_checker.mag"
GDS = BASE / "flag_checker.gds"

RECORD_TYPES = {
    0x00: "HEADER", 0x01: "BGNLIB", 0x02: "LIBNAME", 0x03: "UNITS", 0x04: "ENDLIB",
    0x05: "BGNSTR", 0x06: "STRNAME", 0x07: "ENDSTR", 0x08: "BOUNDARY", 0x09: "PATH",
    0x0A: "SREF", 0x0B: "AREF", 0x0C: "TEXT", 0x0D: "LAYER", 0x0E: "DATATYPE",
    0x0F: "WIDTH", 0x10: "XY", 0x11: "ENDEL", 0x12: "SNAME", 0x13: "COLROW",
    0x16: "TEXTTYPE", 0x17: "PRESENTATION", 0x19: "STRING", 0x1A: "STRANS",
    0x1B: "MAG", 0x1C: "ANGLE", 0x21: "PATHTYPE", 0x2D: "BOX", 0x2E: "BOXTYPE",
}

GDS_TO_LAYER = {67: "li", 68: "metal1", 69: "metal2", 70: "metal3", 71: "metal4", 72: "metal5"}
PIN_IGNORE = {"VPWR", "VGND", "VPB", "VNB"}
VIA_PAIRS = {
    "viali": ("li", "metal1"),
    "via1": ("metal1", "metal2"),
    "via2": ("metal2", "metal3"),
    "via3": ("metal3", "metal4"),
    "via4": ("metal4", "metal5"),
}

class DSU:
    def __init__(self):
        self.parent = []
    def add(self):
        self.parent.append(len(self.parent))
        return len(self.parent) - 1
    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x
    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra

def real8(data):
    if not data or all(b == 0 for b in data):
        return 0.0
    sign = -1 if (data[0] & 0x80) else 1
    exp = (data[0] & 0x7F) - 64
    mant = 0
    for b in data[1:]:
        mant = (mant << 8) | b
    return sign * (mant / (1 << 56)) * (16 ** exp)

def parse_value(dtype, data):
    if dtype == 0:
        return None
    if dtype == 1:
        return int.from_bytes(data, "big")
    if dtype == 2:
        return list(struct.unpack(">" + "h" * (len(data) // 2), data))
    if dtype == 3:
        return list(struct.unpack(">" + "i" * (len(data) // 4), data))
    if dtype == 5:
        return [real8(data[i:i+8]) for i in range(0, len(data), 8)]
    if dtype == 6:
        return data.rstrip(b"\0").decode("ascii", "replace")
    return data

def gds_records(path):
    data = path.read_bytes()
    i = 0
    while i < len(data):
        length, rtype, dtype = struct.unpack(">HBB", data[i:i+4])
        i += 4
        payload = data[i:i+length-4]
        i += length - 4
        yield RECORD_TYPES.get(rtype, hex(rtype)), parse_value(dtype, payload)

def parse_gds(path):
    cells = {}
    cur = None
    elem = None
    for typ, val in gds_records(path):
        if typ == "BGNSTR":
            cur = {"name": None, "elems": []}
        elif typ == "STRNAME":
            cur["name"] = val
        elif typ in {"BOUNDARY", "PATH", "SREF", "AREF", "TEXT", "BOX"}:
            elem = {"type": typ}
        elif elem is not None and typ in {
            "LAYER", "DATATYPE", "TEXTTYPE", "WIDTH", "PATHTYPE", "BOXTYPE", "SNAME",
            "STRANS", "MAG", "ANGLE", "PRESENTATION", "COLROW",
        }:
            elem[typ.lower()] = val[0] if isinstance(val, list) and len(val) == 1 else val
        elif typ == "XY" and elem is not None:
            elem["xy"] = list(zip(val[0::2], val[1::2]))
        elif typ == "STRING" and elem is not None:
            elem["string"] = val
        elif typ == "ENDEL":
            if cur is not None and elem is not None:
                cur["elems"].append(elem)
            elem = None
        elif typ == "ENDSTR":
            cells[cur["name"]] = cur["elems"]
            cur = None
    return cells

def parse_magic(path):
    rects_by_layer = collections.defaultdict(list)
    labels = []
    instances = []
    section = None
    pending_box = None
    pending_use = None
    for line in path.read_text().splitlines():
        if line.startswith("<<"):
            section = line.strip()[3:-3].strip()
        elif line.startswith("rect "):
            x1, y1, x2, y2 = map(int, line.split()[1:5])
            rects_by_layer[section].append((min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2)))
        elif line.startswith("flabel "):
            parts = line.split()
            layer = parts[1]
            x1, y1, x2, y2 = map(int, parts[3:7])
            labels.append((parts[-1], layer, (x1 + x2) / 2, (y1 + y2) / 2))
        elif line.startswith("box "):
            pending_box = tuple(map(int, line.split()[1:5]))
        elif line.startswith("use "):
            p = line.split()
            pending_use = (p[1], p[2], pending_box)
        elif line.startswith("transform ") and pending_use:
            tr = tuple(map(int, line.split()[1:7]))
            instances.append((*pending_use, tr))
            pending_use = None
    return rects_by_layer, labels, instances

def polygon_from_gds_xy(xy):
    poly = Polygon([(x / 5.0, y / 5.0) for x, y in xy])
    return poly if poly.is_valid else poly.buffer(0)

def extract_cell_pins(cells):
    cell_shapes = collections.defaultdict(lambda: collections.defaultdict(list))
    for cname, elems in cells.items():
        if not cname.startswith("sky130_fd_sc_hd__"):
            continue
        for e in elems:
            if e["type"] == "BOUNDARY" and e.get("layer") in GDS_TO_LAYER and "xy" in e:
                poly = polygon_from_gds_xy(e["xy"])
                if not poly.is_empty:
                    cell_shapes[cname][GDS_TO_LAYER[e["layer"]]].append(poly)

    cell_pins = {}
    for cname, elems in cells.items():
        if not cname.startswith("sky130_fd_sc_hd__"):
            continue
        pins = collections.defaultdict(list)
        for e in elems:
            if e["type"] != "TEXT" or e.get("layer") not in GDS_TO_LAYER:
                continue
            pin = e.get("string")
            if not pin or pin in PIN_IGNORE or pin.endswith(("_1", "_2")):
                continue
            layer = GDS_TO_LAYER[e["layer"]]
            pt = Point(e["xy"][0][0] / 5.0, e["xy"][0][1] / 5.0)
            matched = False
            for poly in cell_shapes[cname][layer]:
                if poly.covers(pt):
                    pins[pin].append((layer, poly))
                    matched = True
            if not matched:
                pins[pin].append((layer, pt.buffer(0.1)))
        deduped = {}
        for pin, entries in pins.items():
            seen = set()
            deduped[pin] = []
            for layer, poly in entries:
                key = (layer, tuple(round(v, 3) for v in poly.bounds), round(poly.area, 3))
                if key not in seen:
                    seen.add(key)
                    deduped[pin].append((layer, poly))
        cell_pins[cname] = deduped
    return cell_pins

def extract_netlist():
    cells = parse_gds(GDS)
    rects_by_layer, labels, instances = parse_magic(MAG)
    cell_pins = extract_cell_pins(cells)

    dsu = DSU()
    objs = []
    by_layer = collections.defaultdict(list)
    pin_obj_ids = {}
    label_obj_ids = {}

    def add_obj(layer, geom, kind, name=None):
        oid = dsu.add()
        objs.append({"layer": layer, "geom": geom, "kind": kind, "name": name})
        by_layer[layer].append(oid)
        return oid

    for layer in ["metal1", "metal2", "metal3", "metal4", "metal5"]:
        for r in rects_by_layer[layer]:
            add_obj(layer, box(*r), "route")

    for cell, inst, _bbox, tr in instances:
        if any(x in cell for x in ["fill", "decap", "tapvpwrvgnd"]):
            continue
        a, b, c, d, e, f = tr
        for pin, entries in cell_pins.get(cell, {}).items():
            ids = []
            for layer, poly in entries:
                geom = affine_transform(poly, [a, b, d, e, c, f])
                ids.append(add_obj(layer, geom, "pin", f"{inst}/{pin}"))
            for oid in ids[1:]:
                dsu.union(ids[0], oid)
            pin_obj_ids[(inst, pin)] = ids

    for text, layer, x, y in labels:
        if layer in ["metal1", "metal2", "metal3", "metal4", "metal5"]:
            label_obj_ids[text] = add_obj(layer, Point(x, y).buffer(0.1), "label", text)

    def union_same_layer(layer):
        ids = by_layer[layer]
        geoms = [objs[i]["geom"] for i in ids]
        if not geoms:
            return
        tree = STRtree(geoms)
        for i, geom in enumerate(geoms):
            for j in tree.query(geom):
                j = int(j)
                if j > i and (geom.intersects(geoms[j]) or geom.touches(geoms[j])):
                    dsu.union(ids[i], ids[j])

    for layer in ["li", "metal1", "metal2", "metal3", "metal4", "metal5"]:
        union_same_layer(layer)

    layer_trees = {}
    for layer, ids in by_layer.items():
        geoms = [objs[i]["geom"] for i in ids]
        layer_trees[layer] = (ids, geoms, STRtree(geoms) if geoms else None)

    via_added = []
    for vlay, (lo, hi) in VIA_PAIRS.items():
        for r in rects_by_layer[vlay]:
            geom = box(*r)
            vid = dsu.add()
            objs.append({"layer": vlay, "geom": geom, "kind": "via", "name": vlay})
            via_added.append((vid, geom, {lo, hi}))
            for layer in (lo, hi):
                ids, geoms, tree = layer_trees.get(layer, ([], [], None))
                if tree is None:
                    continue
                for j in tree.query(geom):
                    j = int(j)
                    if geom.intersects(geoms[j]) or geom.touches(geoms[j]):
                        dsu.union(vid, ids[j])

    # Magic contact stacks sometimes rely on implicit intermediate metal enclosures.
    for i, (ida, ga, la) in enumerate(via_added):
        for idb, gb, lb in via_added[i+1:]:
            if not la.isdisjoint(lb) and (ga.intersects(gb) or ga.touches(gb)):
                dsu.union(ida, idb)

    root_names = collections.defaultdict(list)
    for text, oid in label_obj_ids.items():
        root_names[dsu.find(oid)].append(text)

    def net_of(oid):
        root = dsu.find(oid)
        return "/".join(sorted(root_names[root])) if root_names[root] else f"n{root}"

    pin_nets = {}
    for key, ids in pin_obj_ids.items():
        nets = sorted({net_of(i) for i in ids})
        if len(nets) != 1:
            raise RuntimeError(f"ambiguous pin net {key}: {nets}")
        pin_nets[key] = nets[0]

    netlist = []
    for cell, inst, _bbox, _tr in instances:
        if any(x in cell for x in ["fill", "decap", "tapvpwrvgnd"]):
            continue
        pins = {pin: pin_nets[(inst, pin)] for pin in cell_pins.get(cell, {})}
        netlist.append({"inst": inst, "cell": cell.replace("sky130_fd_sc_hd__", ""), "pins": pins})
    return netlist

def eval_cell(cell, pins, vals):
    def ready(names):
        return all(pins.get(n) in vals for n in names)
    def need(names):
        if not ready(names):
            raise KeyError
        return [vals[pins[n]] for n in names]
    def lit(pin):
        v = vals[pins[pin]]
        return (not v) if pin.endswith("_N") else v

    if cell.startswith(("clkbuf", "clkdlybuf")):
        a, = need(["A"]); return "X", a
    if cell.startswith("inv"):
        a, = need(["A"]); return "Y", not a
    if cell.startswith("xnor2"):
        a, b = need(["A", "B"]); return "Y", not (a ^ b)
    if cell.startswith("and"):
        ins = [p for p in pins if p != "X"]
        if not ready(ins): raise KeyError
        return "X", all(lit(p) for p in ins)
    if cell.startswith("or"):
        ins = [p for p in pins if p != "X"]
        if not ready(ins): raise KeyError
        return "X", any(lit(p) for p in ins)
    if cell.startswith("nand"):
        ins = [p for p in pins if p != "Y"]
        if not ready(ins): raise KeyError
        return "Y", not all(lit(p) for p in ins)
    if cell.startswith("nor"):
        ins = [p for p in pins if p != "Y"]
        if not ready(ins): raise KeyError
        return "Y", not any(lit(p) for p in ins)

    if cell.startswith("a21o_"):
        a1, a2, b1 = need(["A1", "A2", "B1"]); return "X", (a1 and a2) or b1
    if cell.startswith("a21oi_"):
        a1, a2, b1 = need(["A1", "A2", "B1"]); return "Y", not ((a1 and a2) or b1)
    if cell.startswith("a21boi"):
        a1, a2, b1n = need(["A1", "A2", "B1_N"]); return "Y", not ((a1 and a2) or (not b1n))
    if cell.startswith("a211o_"):
        a1, a2, b1, c1 = need(["A1", "A2", "B1", "C1"]); return "X", (a1 and a2) or b1 or c1
    if cell.startswith("a211oi_"):
        a1, a2, b1, c1 = need(["A1", "A2", "B1", "C1"]); return "Y", not ((a1 and a2) or b1 or c1)
    if cell.startswith("a31oi"):
        a1, a2, a3, b1 = need(["A1", "A2", "A3", "B1"]); return "Y", not ((a1 and a2 and a3) or b1)
    if cell.startswith("a311o"):
        a1, a2, a3, b1, c1 = need(["A1", "A2", "A3", "B1", "C1"]); return "X", (a1 and a2 and a3) or b1 or c1
    if cell.startswith("a22o"):
        a1, a2, b1, b2 = need(["A1", "A2", "B1", "B2"]); return "X", (a1 and a2) or (b1 and b2)
    if cell.startswith("a32o"):
        a1, a2, a3, b1, b2 = need(["A1", "A2", "A3", "B1", "B2"]); return "X", (a1 and a2 and a3) or (b1 and b2)
    if cell.startswith("a2bb2oi"):
        a1n, a2n, b1, b2 = need(["A1_N", "A2_N", "B1", "B2"]); return "Y", not (((not a1n) and (not a2n)) or (b1 and b2))

    if cell.startswith("o21a_"):
        a1, a2, b1 = need(["A1", "A2", "B1"]); return "X", (a1 or a2) and b1
    if cell.startswith("o21ai_"):
        a1, a2, b1 = need(["A1", "A2", "B1"]); return "Y", not ((a1 or a2) and b1)
    if cell.startswith("o21ba") and not cell.startswith("o21bai"):
        a1, a2, b1n = need(["A1", "A2", "B1_N"]); return "X", (a1 or a2) and (not b1n)
    if cell.startswith("o21bai"):
        a1, a2, b1n = need(["A1", "A2", "B1_N"]); return "Y", not ((a1 or a2) and (not b1n))
    if cell.startswith("o31ai"):
        a1, a2, a3, b1 = need(["A1", "A2", "A3", "B1"]); return "Y", not ((a1 or a2 or a3) and b1)
    if cell.startswith("o32a"):
        a1, a2, a3, b1, b2 = need(["A1", "A2", "A3", "B1", "B2"]); return "X", (a1 or a2 or a3) and (b1 or b2)
    if cell.startswith("o41a"):
        a1, a2, a3, a4, b1 = need(["A1", "A2", "A3", "A4", "B1"]); return "X", (a1 or a2 or a3 or a4) and b1
    if cell.startswith("o2111a"):
        a1, a2, b1, c1, d1 = need(["A1", "A2", "B1", "C1", "D1"]); return "X", (a1 or a2) and b1 and c1 and d1
    if cell.startswith("o22a"):
        a1, a2, b1, b2 = need(["A1", "A2", "B1", "B2"]); return "X", (a1 or a2) and (b1 or b2)
    if cell.startswith("o2bb2a"):
        a1n, a2n, b1, b2 = need(["A1_N", "A2_N", "B1", "B2"]); return "X", ((not a1n) or (not a2n)) and (b1 or b2)

    raise NotImplementedError(cell)

def solve_flag(netlist):
    comb = [r for r in netlist if not r["cell"].startswith("dfxtp")]
    dffs = [r for r in netlist if r["cell"].startswith("dfxtp")]
    state_nets = [r["pins"]["Q"] for r in dffs]
    d_nets = [r["pins"]["D"] for r in dffs]

    def eval_comb(state, ch, reset_n=True):
        vals = {"clk": False, "reset_n": bool(reset_n)}
        for i in range(7):
            vals[f"character[{i}]"] = bool((ch >> i) & 1)
        for net, bit in zip(state_nets, state):
            vals[net] = bool(bit)
        pending = comb[:]
        for _ in range(1000):
            progress = False
            rest = []
            for cell in pending:
                try:
                    out_pin, value = eval_cell(cell["cell"], cell["pins"], vals)
                except KeyError:
                    rest.append(cell)
                    continue
                vals[cell["pins"][out_pin]] = value
                progress = True
            pending = rest
            if not pending:
                break
            if not progress:
                raise RuntimeError(f"combinational evaluation stuck on {len(pending)} cells")
        return vals

    def state_from_int(x):
        return tuple(bool((x >> i) & 1) for i in range(len(state_nets)))
    def state_to_int(s):
        return sum((1 << i) for i, bit in enumerate(s) if bit)
    def step(state_int, ch):
        vals = eval_comb(state_from_int(state_int), ch, True)
        return state_to_int(tuple(vals[n] for n in d_nets))
    def is_found(state_int):
        return bool(eval_comb(state_from_int(state_int), 0, True).get("found_flag"))

    q = deque([(0, "")])
    seen = {0}
    alphabet = [ord(c) for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_{}"]
    while q:
        state, text = q.popleft()
        if is_found(state):
            return text
        if len(text) > 80:
            continue
        for ch in alphabet:
            nxt = step(state, ch)
            if nxt not in seen:
                seen.add(nxt)
                q.append((nxt, text + chr(ch)))
    raise RuntimeError("flag path not found")

def main():
    for path in (MAG, GDS):
        if not path.exists():
            raise SystemExit(f"missing {path.name}")
    netlist = extract_netlist()
    flag = solve_flag(netlist)
    print(f"<FLAG>{flag}</FLAG>")

if __name__ == "__main__":
    main()
