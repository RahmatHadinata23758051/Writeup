#!/usr/bin/env python3
"""Solve UCTF forensic challenge: Quiet Twin.

The script:
1. extracts quiet_twin.zip;
2. parses all ASCII PLY scans and calibration_log.json;
3. replaces a bad active extrinsic with its fallback candidate;
4. reconstructs the point cloud in world coordinates;
5. isolates the end wall and renders the etched token;
6. segments the 16 hexadecimal characters and reads them with Tesseract.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw


HEX_CHARS = "0123456789abcdef"
EXPECTED_CHARACTER_COUNT = 22  # uctf{ + 16 hexadecimal chars + }


def read_ascii_ply(path: Path) -> np.ndarray:
    """Read x, y, z vertices from an ASCII PLY file."""
    vertex_count: int | None = None

    with path.open("r", encoding="ascii") as handle:
        first = handle.readline().strip()

        if first != "ply":
            raise RuntimeError(f"{path.name}: invalid PLY signature")

        while True:
            line = handle.readline()

            if not line:
                raise RuntimeError(f"{path.name}: truncated PLY header")

            stripped = line.strip()

            if (
                stripped.startswith("format ")
                and stripped != "format ascii 1.0"
            ):
                raise RuntimeError(
                    f"{path.name}: only ASCII PLY is supported"
                )

            if stripped.startswith("element vertex "):
                vertex_count = int(stripped.split()[2])

            if stripped == "end_header":
                break

        if vertex_count is None:
            raise RuntimeError(
                f"{path.name}: vertex count is missing"
            )

        points = np.loadtxt(
            handle,
            dtype=np.float32,
            max_rows=vertex_count,
            usecols=(0, 1, 2),
        )

    points = np.atleast_2d(points)

    if len(points) != vertex_count:
        raise RuntimeError(
            f"{path.name}: expected {vertex_count} vertices, "
            f"got {len(points)}"
        )

    return points


def extract_archive(
    archive: Path,
    destination: Path,
) -> Path:
    """Extract the challenge archive and return its data directory."""
    if destination.exists():
        shutil.rmtree(destination)

    destination.mkdir(parents=True)

    with zipfile.ZipFile(archive) as zf:
        for member in zf.infolist():
            member_path = Path(member.filename)

            if (
                member_path.is_absolute()
                or ".." in member_path.parts
            ):
                raise RuntimeError(
                    f"unsafe ZIP member: {member.filename}"
                )

        zf.extractall(destination)

    logs = list(
        destination.rglob("calibration_log.json")
    )

    if len(logs) != 1:
        raise RuntimeError(
            "calibration_log.json was not found uniquely"
        )

    return logs[0].parent


def reconstruct(
    data_dir: Path,
) -> tuple[np.ndarray, list[str]]:
    """Apply the calibration transforms and merge all scans."""
    log_path = data_dir / "calibration_log.json"

    calibration = json.loads(
        log_path.read_text(encoding="utf-8")
    )

    scans = calibration["scans"]
    extrinsics = calibration["extrinsics"]

    merged: list[np.ndarray] = []
    corrections: list[str] = []

    for scan_name in sorted(scans):
        scan_info = scans[scan_name]
        active_name = scan_info["active_extrinsic"]

        # Fallback merupakan kalibrasi lama sebelum update rusak.
        # scan_09 memakai E09_ACTIVE_BAD dan menyediakan E09.
        extrinsic_name = scan_info.get(
            "fallback_candidate",
            active_name,
        )

        if extrinsic_name != active_name:
            corrections.append(
                f"{scan_name}: "
                f"{active_name} -> {extrinsic_name}"
            )

        if extrinsic_name not in extrinsics:
            raise RuntimeError(
                f"{scan_name}: unknown extrinsic "
                f"{extrinsic_name!r}"
            )

        transform = extrinsics[extrinsic_name]

        rotation = np.asarray(
            transform["R"],
            dtype=np.float32,
        )

        translation = np.asarray(
            transform["t"],
            dtype=np.float32,
        )

        if (
            rotation.shape != (3, 3)
            or translation.shape != (3,)
        ):
            raise RuntimeError(
                f"{extrinsic_name}: malformed transform"
            )

        local_points = read_ascii_ply(
            data_dir / scan_name
        )

        # Rumus pada JSON:
        #
        # p_world = R @ p_local + t
        #
        # Untuk array NumPy N x 3:
        #
        # p_world = p_local @ R.T + t
        world_points = (
            local_points @ rotation.T
            + translation
        )

        merged.append(world_points)

    return np.vstack(merged), corrections


def write_ascii_ply(
    path: Path,
    points: np.ndarray,
) -> None:
    """Save the reconstructed point cloud."""
    header = (
        "ply\n"
        "format ascii 1.0\n"
        f"element vertex {len(points)}\n"
        "property float x\n"
        "property float y\n"
        "property float z\n"
        "end_header\n"
    )

    with path.open("w", encoding="ascii") as handle:
        handle.write(header)

        np.savetxt(
            handle,
            points,
            fmt="%.6f %.6f %.6f",
        )


def find_character_runs(
    wall_points: np.ndarray,
    y_range: tuple[float, float],
    z_range: tuple[float, float],
) -> list[tuple[float, float]]:
    """Locate character columns using point-density profile."""
    y_min, y_max = y_range
    z_min, z_max = z_range

    band = wall_points[
        (wall_points[:, 2] >= z_min)
        & (wall_points[:, 2] <= z_max)
    ]

    bins = 2000

    histogram, edges = np.histogram(
        band[:, 1],
        bins=bins,
        range=(y_min, y_max),
    )

    smoothed = np.convolve(
        histogram,
        np.ones(9),
        mode="same",
    )

    # Bagian pinggir adalah frame dinding.
    interior_min = y_min + 0.20
    interior_max = y_max - 0.20

    threshold_order = (
        [20, 15, 10, 5]
        + list(range(21, 81))
    )

    for threshold in threshold_order:
        occupied = smoothed > threshold

        runs: list[tuple[float, float]] = []
        start: int | None = None

        for index, value in enumerate(occupied):
            if value and start is None:
                start = index

            elif not value and start is not None:
                if index - start > 2:
                    runs.append(
                        (
                            float(edges[start]),
                            float(edges[index]),
                        )
                    )

                start = None

        if start is not None:
            runs.append(
                (
                    float(edges[start]),
                    float(edges[-1]),
                )
            )

        runs = [
            run
            for run in runs
            if (
                run[0] > interior_min
                and run[1] < interior_max
            )
        ]

        if len(runs) == EXPECTED_CHARACTER_COUNT:
            return runs

    raise RuntimeError(
        "failed to segment the expected "
        "22 characters from the wall"
    )


def render_points(
    points: np.ndarray,
    y_range: tuple[float, float],
    z_range: tuple[float, float],
    output: Path,
    width: int,
    height: int,
    radius: int = 2,
) -> None:
    """Create an orthographic Y/Z point-cloud image."""
    y_min, y_max = y_range
    z_min, z_max = z_range

    selected = points[
        (points[:, 1] >= y_min)
        & (points[:, 1] <= y_max)
        & (points[:, 2] >= z_min)
        & (points[:, 2] <= z_max)
    ]

    image = Image.new(
        "L",
        (width, height),
        255,
    )

    draw = ImageDraw.Draw(image)

    px = (
        (selected[:, 1] - y_min)
        / (y_max - y_min)
        * (width - 1)
    ).astype(np.int32)

    py = (
        (z_max - selected[:, 2])
        / (z_max - z_min)
        * (height - 1)
    ).astype(np.int32)

    for x, y in zip(px, py, strict=True):
        draw.ellipse(
            (
                x - radius,
                y - radius,
                x + radius,
                y + radius,
            ),
            fill=0,
        )

    image.save(output)


def render_character(
    wall_points: np.ndarray,
    y_run: tuple[float, float],
    z_range: tuple[float, float],
    output: Path,
) -> None:
    """Render one segmented glyph in a normalized image."""
    y0, y1 = y_run
    padding = 0.004

    y0 -= padding
    y1 += padding

    width = 180
    height = 420
    margin = 10

    z0, z1 = z_range

    selected = wall_points[
        (wall_points[:, 1] >= y0)
        & (wall_points[:, 1] <= y1)
        & (wall_points[:, 2] >= z0)
        & (wall_points[:, 2] <= z1)
    ]

    image = Image.new(
        "L",
        (width, height),
        255,
    )

    draw = ImageDraw.Draw(image)

    px = (
        (selected[:, 1] - y0)
        / (y1 - y0)
        * (width - 2 * margin - 1)
        + margin
    ).astype(np.int32)

    py = (
        (z1 - selected[:, 2])
        / (z1 - z0)
        * (height - 2 * margin - 1)
        + margin
    ).astype(np.int32)

    for x, y in zip(px, py, strict=True):
        draw.ellipse(
            (
                x - 2,
                y - 2,
                x + 2,
                y + 2,
            ),
            fill=0,
        )

    image.save(output)


def tesseract_character(
    image: Path,
    psm: int,
) -> str | None:
    """OCR one hexadecimal glyph."""
    result = subprocess.run(
        [
            "tesseract",
            str(image),
            "stdout",
            "--psm",
            str(psm),
            "-c",
            (
                "tessedit_char_whitelist="
                f"{HEX_CHARS}"
            ),
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ).stdout.lower()

    cleaned = re.sub(
        f"[^{HEX_CHARS}]",
        "",
        result,
    )

    if len(cleaned) == 1:
        return cleaned

    return None


def decode_payload(
    wall_points: np.ndarray,
    runs: list[tuple[float, float]],
    z_range: tuple[float, float],
    character_dir: Path,
) -> str:
    """Read 16 hexadecimal characters inside uctf{...}."""
    if shutil.which("tesseract") is None:
        raise RuntimeError(
            "tesseract is required for automatic OCR"
        )

    character_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Karakter 0..4 = uctf{
    # Karakter terakhir = }
    payload_runs = runs[5:-1]

    if len(payload_runs) != 16:
        raise RuntimeError(
            "segmentation did not yield "
            "a 16-character payload"
        )

    decoded: list[str] = []

    for index, run in enumerate(payload_runs):
        image_path = (
            character_dir
            / f"hex_{index:02d}.png"
        )

        render_character(
            wall_points,
            run,
            z_range,
            image_path,
        )

        # PSM 13 cocok untuk mayoritas glyph.
        # PSM 10 digunakan sebagai fallback.
        character = tesseract_character(
            image_path,
            psm=13,
        )

        if character is None:
            character = tesseract_character(
                image_path,
                psm=10,
            )

        if character is None:
            raise RuntimeError(
                f"OCR failed for payload "
                f"character {index}; "
                f"inspect {image_path}"
            )

        decoded.append(character)

    token = "".join(decoded)

    if not re.fullmatch(
        r"[0-9a-f]{16}",
        token,
    ):
        raise RuntimeError(
            f"invalid decoded hexadecimal "
            f"token: {token!r}"
        )

    return token


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Reconstruct Quiet Twin and "
            "recover the etched token."
        )
    )

    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        default=Path("quiet_twin.zip"),
        help=(
            "quiet_twin.zip or an extracted "
            "challenge directory"
        ),
    )

    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("quiet_twin_output"),
        help="directory for reconstructed artifacts",
    )

    args = parser.parse_args()

    try:
        args.output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        if (
            args.input.is_file()
            and args.input.suffix.lower() == ".zip"
        ):
            data_dir = extract_archive(
                args.input,
                args.output_dir / "extracted",
            )

        elif args.input.is_dir():
            data_dir = args.input

        else:
            raise RuntimeError(
                f"input was not found: {args.input}"
            )

        points, corrections = reconstruct(
            data_dir
        )

        scene_path = (
            args.output_dir
            / "reconstructed_scene.ply"
        )

        write_ascii_ply(
            scene_path,
            points,
        )

        point_min = points.min(axis=0)
        point_max = points.max(axis=0)

        # Tulisan berada pada dinding ujung positive-X.
        wall = points[
            points[:, 0]
            > point_max[0] - 0.22
        ]

        # Area bersih yang berisi tulisan.
        y_range = (-1.90, 1.90)
        z_range = (1.04, 1.52)

        runs = find_character_runs(
            wall,
            y_range,
            z_range,
        )

        token_y_range = (
            runs[0][0] - 0.03,
            runs[-1][1] + 0.03,
        )

        token_image = (
            args.output_dir
            / "authorization_token.png"
        )

        render_points(
            wall,
            token_y_range,
            z_range,
            token_image,
            width=3200,
            height=500,
            radius=2,
        )

        token = decode_payload(
            wall,
            runs,
            z_range,
            args.output_dir / "characters",
        )

    except (
        OSError,
        ValueError,
        KeyError,
        RuntimeError,
        zipfile.BadZipFile,
        subprocess.CalledProcessError,
    ) as error:
        print(
            f"[-] {error}",
            file=sys.stderr,
        )
        raise SystemExit(1)

    print(
        f"[+] merged points       : "
        f"{len(points)}"
    )

    for correction in corrections:
        print(
            f"[+] calibration rollback: "
            f"{correction}"
        )

    print(
        f"[+] scene bounds        : "
        f"min={point_min}, max={point_max}"
    )

    print(
        f"[+] reconstructed PLY   : "
        f"{scene_path}"
    )

    print(
        f"[+] token render        : "
        f"{token_image}"
    )

    print(
        f"[+] token               : "
        f"{token}"
    )

    print(f"uctf{{{token}}}")


if __name__ == "__main__":
    main()
