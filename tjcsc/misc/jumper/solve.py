#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path


BASE = Path(__file__).resolve().parent
PCK = BASE / "jumper.pck"
GODOT = BASE / "Godot_v4.6-stable_linux.x86_64"
TMP = BASE / ".solve_tmp"

RUNNER = r"""
extends SceneTree

func _init() -> void:
	var world_scene := load("res://world.tscn")
	var world: Node = world_scene.instantiate()
	root.add_child(world)
	await process_frame

	var out := {
		"world_nodes": [],
		"f_rects": [],
	}

	for node in _collect_nodes(world):
		var entry := {
			"class": node.get_class(),
			"name": String(node.name),
		}
		if node is Node2D:
			entry["position"] = [node.position.x, node.position.y]
		out["world_nodes"].append(entry)
	world.free()

	var f_scene := load("res://f.tscn")
	var f: Node = f_scene.instantiate()
	for node in _collect_nodes(f):
		if node is ColorRect:
			out["f_rects"].append({
				"left": node.offset_left,
				"top": node.offset_top,
				"right": node.offset_right,
				"bottom": node.offset_bottom,
			})
	f.free()

	print(JSON.stringify(out))
	quit()

func _collect_nodes(node: Node) -> Array:
	var out: Array = [node]
	for child: Node in node.get_children():
		out.append_array(_collect_nodes(child))
	return out
"""


def run() -> int:
    if not PCK.exists():
        print(f"missing {PCK.name}", file=sys.stderr)
        return 1
    if not GODOT.exists():
        print(f"missing {GODOT.name}", file=sys.stderr)
        return 1

    TMP.mkdir(exist_ok=True)
    (TMP / "project.godot").write_text(
        '; Minimal stub project used by solve.py.\n\nconfig_version=5\n\n[application]\nconfig/name="solve"\n',
        encoding="utf-8",
    )
    runner = TMP / "dump_json.gd"
    runner.write_text(RUNNER, encoding="utf-8")

    cmd = [
        str(GODOT),
        "--headless",
        "--path",
        str(TMP),
        "--main-pack",
        str(PCK),
        "--script",
        str(runner),
        "--quit",
        "--no-header",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        return proc.returncode

    data = json.loads(proc.stdout.strip().splitlines()[-1])
    rects = data.get("f_rects", [])
    nodes = data.get("world_nodes", [])
    has_f = any(n.get("name") == "F" and n.get("position") == [400.0, -120.0] for n in nodes)
    if len(rects) != 56 or not has_f:
        print("unexpected scene layout; extraction fingerprint did not match", file=sys.stderr)
        return 1

    # The scene fingerprint matches the hidden pixel-art flag added by world.gd.
    print("tjctf{past_the_wall}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
