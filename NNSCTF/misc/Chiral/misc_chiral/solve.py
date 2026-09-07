#!/usr/bin/env python3
from pathlib import Path
from collections import defaultdict, deque

try:
    from rdkit import Chem
except ImportError as e:
    raise SystemExit("RDKit dibutuhkan: pip install rdkit") from e

BASE = Path(__file__).resolve().parent
MOLFILE = BASE / "chiral.mol"


def branch_size(adj, start, parent, backbone):
    q = deque([(start, parent)])
    seen = {parent}
    total = 0
    while q:
        v, p = q.popleft()
        if v in backbone or v in seen:
            continue
        seen.add(v)
        total += 1
        for u in adj[v]:
            if u != p:
                q.append((u, v))
    return total


def main():
    mol = Chem.MolFromMolFile(str(MOLFILE), sanitize=True, removeHs=False)
    if mol is None:
        raise SystemExit("gagal parse chiral.mol")

    Chem.AssignStereochemistry(mol, force=True, cleanIt=True)

    atoms = list(mol.GetAtoms())
    f_atoms = [a.GetIdx() for a in atoms if a.GetSymbol() == "F"]
    br_atoms = [a.GetIdx() for a in atoms if a.GetSymbol() == "Br"]
    if len(f_atoms) != 1 or len(br_atoms) != 1:
        raise SystemExit("terminal F/Br tidak unik")

    start, end = f_atoms[0], br_atoms[0]
    path = list(Chem.GetShortestPath(mol, start, end))
    if not path:
        raise SystemExit("backbone F -> Br tidak ketemu")

    adj = defaultdict(list)
    for b in mol.GetBonds():
        a1, a2 = b.GetBeginAtomIdx(), b.GetEndAtomIdx()
        adj[a1].append(a2)
        adj[a2].append(a1)

    chiral = dict(Chem.FindMolChiralCenters(
        mol,
        includeUnassigned=False,
        useLegacyImplementation=False,
    ))

    backbone = set(path)
    nibbles = []
    for atom_idx in path[1:-1]:
        desc = chiral.get(atom_idx)
        if desc not in ("R", "S"):
            raise SystemExit(f"atom {atom_idx + 1} bukan chiral center valid")

        branches = [n for n in adj[atom_idx] if n not in backbone]
        if len(branches) != 1:
            raise SystemExit(f"atom {atom_idx + 1} punya {len(branches)} side-chain")

        length = branch_size(adj, branches[0], atom_idx, backbone)
        if not (1 <= length <= 8):
            raise SystemExit(f"panjang side-chain invalid di atom {atom_idx + 1}: {length}")

        # R/S menyimpan bit tertinggi nibble, panjang side-chain 1..8 menyimpan 3 bit bawah.
        high_bit = 0 if desc == "R" else 1
        nibbles.append((high_bit << 3) | (length - 1))

    if len(nibbles) % 2:
        raise SystemExit("jumlah nibble ganjil")

    data = bytes((nibbles[i] << 4) | nibbles[i + 1] for i in range(0, len(nibbles), 2))
    flag = data.decode("ascii")
    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
