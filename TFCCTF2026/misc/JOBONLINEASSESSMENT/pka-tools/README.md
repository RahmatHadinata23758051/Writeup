# cisco-pka-to-xml

Convert Cisco Packet Tracer activity files (`.pka`) and saved networks (`.pkt`) to readable XML and back.

This is a clean-room, MIT-licensed Python implementation of the file format originally documented by [Mirco De Zorzi (`mircodz/pka2xml`)](https://github.com/mircodz/pka2xml). It works against modern Packet Tracer versions (7.x, 8.x, **9.x**) where older XOR-only tools such as [`axcheron/ptexplorer`](https://github.com/axcheron/ptexplorer) fail.

> Disclaimer: this tool is for educational and interoperability purposes — for example to inspect your own activity files, audit answer keys, or migrate topologies between versions. It does not bypass any DRM, license check, or activity grading mechanism. Use it on files you have the right to read.

---

## Table of contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Decode a `.pka` to XML](#decode-a-pka-to-xml)
  - [Encode XML back into a `.pka`](#encode-xml-back-into-a-pka)
  - [Use as a Python library](#use-as-a-python-library)
- [What you get in the XML](#what-you-get-in-the-xml)
- [Troubleshooting](#troubleshooting)
- [Project layout](#project-layout)
- [Contributing](#contributing)
- [License](#license)
- [Credits](#credits)

---

## How it works

A Packet Tracer file is an XML document that has been put through four reversible stages:

1. **zlib compression** with a 4-byte big-endian uncompressed-length prefix.
2. **Position-keyed XOR**: each byte `b[i]` is XORed with `(length - i) & 0xff`.
3. **Twofish-EAX encryption** with the constant key `0x89` repeated 16 times and IV `0x10` repeated 16 times.
4. **Position-keyed XOR + reversal**: each byte `out[length-1-i] = in[i] ^ ((length - i*length) & 0xff)`.

Decoding inverts the pipeline. The Twofish block cipher is the only piece that needs native code; everything else — including the EAX authenticated mode (CMAC + CTR) — is implemented in plain Python in this repository so the only build dependency is a C compiler.

The Twofish reference implementation by Niels Ferguson is vendored under [`vendor/twofish/`](./vendor/twofish/) (also MIT-licensed; see [`vendor/twofish/LICENSE`](./vendor/twofish/LICENSE)).

---

## Requirements

- Python 3.8 or newer
- A C compiler (any of `cc`, `gcc`, `clang`, or `tcc`)
- `patchelf` — only on Linux *and* only if your compiler does not emit a `.note.GNU-stack` section. Modern `gcc`/`clang` do; `tcc` does not. The build script will use `patchelf --clear-execstack` automatically when available.

No third-party Python packages are needed.

---

## Installation

```bash
git clone https://github.com/jeamxn/cisco-pka-to-xml.git
cd cisco-pka-to-xml

# Build the Twofish shared library (one-time)
python build_libtwofish.py
```

This produces `pka2xml/libtwofish.so` (Linux), `libtwofish.dylib` (macOS), or `libtwofish.dll` (Windows) next to the Python package.

If you need to point at an existing build, set the `LIBTWOFISH` environment variable:

```bash
export LIBTWOFISH=/path/to/libtwofish.so
```

### Running the tests

```bash
python tests/test_roundtrip.py
```

The roundtrip test encodes a tiny XML blob and decodes it back. The KAT test runs an official Twofish 128-bit test vector against the native build.

---

## Usage

### Decode a `.pka` to XML

```bash
python -m pka2xml decode path/to/activity.pka activity.xml
```

The output is a single XML document. For activity (`.pka`) files it is wrapped in `<PACKETTRACER5_ACTIVITY>` and typically contains multiple `<PACKETTRACER5>` snapshots (initial network, answer network, etc.). Saved networks (`.pkt`) contain a single `<PACKETTRACER5>` document.

### Encode XML back into a `.pka`

```bash
python -m pka2xml encode activity.xml rebuilt.pka
```

The output is byte-identical in length category but not byte-identical to the original — zlib's deterministic compression depends on the exact compressor build. Packet Tracer will still open it.

### Use as a Python library

```python
from pathlib import Path
from pka2xml import decrypt_pka, encrypt_pka

xml_bytes = decrypt_pka(Path("activity.pka").read_bytes())
Path("activity.xml").write_bytes(xml_bytes)

# round-trip
rebuilt = encrypt_pka(xml_bytes)
Path("rebuilt.pka").write_bytes(rebuilt)
```

`decrypt_pka` raises `pka2xml.PkaError` if the EAX tag does not match or the inner zlib stream is malformed. That almost always means the file is not a Packet Tracer file or was produced by a very old (pre-6.0) version.

---

## What you get in the XML

A small excerpt from a decoded routing activity:

```xml
<PACKETTRACER5_ACTIVITY>
  <VERSION>9.0.0.0810</VERSION>
  <PACKETTRACER5>
    <NETWORK>
      <DEVICES>
        <DEVICE>
          <ENGINE>
            <TYPE model="2811">Router</TYPE>
            <NAME translate="true">R1</NAME>
            ...
            <RUNNING_CONFIG>
              <LINE>interface FastEthernet0/0.10</LINE>
              <LINE> encapsulation dot1Q 10</LINE>
              <LINE> ip address 204.200.10.1 255.255.255.0</LINE>
              ...
            </RUNNING_CONFIG>
          </ENGINE>
        </DEVICE>
        ...
      </DEVICES>
    </NETWORK>
  </PACKETTRACER5>
</PACKETTRACER5_ACTIVITY>
```

Useful tags to grep for once you have the XML:

| Tag                     | Meaning                                         |
| ----------------------- | ----------------------------------------------- |
| `<DEVICE>` / `<NAME>`   | A device node with its display name             |
| `<TYPE model="...">`    | Hardware model (e.g. `2811`, `PC-PT`)           |
| `<RUNNING_CONFIG>`      | The IOS `show running-config` of the device     |
| `<IP>` / `<SUBNET>`     | Interface IP and mask                           |
| `<GATEWAY>`             | Default gateway (on PCs/servers)                |
| `<LINK>`                | A cable: contains the two endpoints             |
| `<COMMAND_LOGS>`        | Hex-encoded CLI history of the device           |

---

## Troubleshooting

| Symptom                                                                                    | Likely cause                                                                          |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------- |
| `libtwofish shared library not found`                                                      | Run `python build_libtwofish.py` first, or set `LIBTWOFISH=/path/to/libtwofish.so`.      |
| `cannot enable executable stack as shared object requires` on Linux when loading the lib   | Install `patchelf` and rerun the build, or rebuild with a modern `gcc` / `clang`.     |
| `EAX authentication tag mismatch — file may be corrupt or wrong key`                       | The input is not a Packet Tracer file produced by version 6.0 or later.               |
| `zlib decompression failed`                                                                | Same as above, or the file was produced by Packet Tracer 5.x (XOR-only — use `ptexplorer`). |
| Output XML opens in PT but text is mangled                                                 | The XML was edited with a non-UTF-8 editor. Save as UTF-8 without BOM.                |

---

## Project layout

```
.
├── pka2xml/                  Python package
│   ├── __init__.py           Public API: Twofish, decrypt_pka, encrypt_pka, PkaError
│   ├── __main__.py           CLI entry point (`python -m pka2xml ...`)
│   ├── build.py              Build script for the native Twofish library
│   └── libtwofish.so         (Generated) Native Twofish blob cipher
├── vendor/
│   └── twofish/              Niels Ferguson's reference Twofish implementation
│       ├── twofish.c
│       ├── twofish.h
│       └── LICENSE           MIT (vendored upstream license)
├── tests/
│   └── test_roundtrip.py     KAT + encode/decode roundtrip
├── examples/
│   └── inspect_devices.py    Walk the decoded XML and print device + IP info
├── CONTRIBUTING.md
├── LICENSE                   MIT (this project)
└── README.md
```

---

## Contributing

Contributions are welcome — bug reports, format quirks for unseen PT versions, new sample files, doc fixes, and platform-specific build tweaks all count. Please read this whole section before opening a PR.

### Ways to contribute

1. **File an issue.** If you have a `.pka` that does not decode, open an issue and attach the file (or a redacted excerpt of the hex dump and Packet Tracer version) plus the exact `PkaError` message.
2. **Submit a pull request.** See the workflow below.
3. **Add an example.** Drop a new script under [`examples/`](./examples/) showing a new way to use the library (topology graph rendering, diff between two activities, batch grading, …).
4. **Improve documentation.** README clarity, more troubleshooting entries, language translations under `docs/`.
5. **Help port to Windows / macOS.** The build script accepts `cc`, `gcc`, `clang`, and `tcc`. Reports of what does and does not work on each platform are very welcome.

### Development workflow

1. **Fork the repository** on GitHub and clone your fork.
   ```bash
   git clone https://github.com/<your-user>/cisco-pka-to-xml.git
   cd cisco-pka-to-xml
   git remote add upstream https://github.com/jeamxn/cisco-pka-to-xml.git
   ```

2. **Create a feature branch.** Branch names should be short and descriptive. Use the prefixes `feat/`, `fix/`, `docs/`, or `chore/`.
   ```bash
   git checkout -b feat/windows-build-support
   ```

3. **Build and test.**
   ```bash
   python build_libtwofish.py
   python tests/test_roundtrip.py
   ```

4. **Make your changes.** Keep diffs focused — one PR per topic. Match the style of surrounding code (PEP 8, four-space indent, type hints on new public functions, snake_case names).

5. **Add or update tests.** If you change behavior, add a test under `tests/`. New tests can use stdlib `unittest` or just plain `assert` statements like the existing ones.

6. **Run the full check before pushing.**
   ```bash
   python build_libtwofish.py
   python tests/test_roundtrip.py
   # If you have ruff/black installed locally:
   # ruff check .
   # black --check .
   ```

7. **Commit with a clear message.** We follow [Conventional Commits](https://www.conventionalcommits.org/) loosely:
   ```
   feat(cli): add --quiet flag to decode subcommand
   fix(eax): handle empty header buffers on 32-bit Python
   docs(readme): document LIBTWOFISH env var
   ```

8. **Open a pull request** against `main`. Describe the motivation, what changed, and how to reproduce or test. Reference any related issues with `Closes #123`.

9. **Respond to review.** Force-push fixups onto your branch (`git push --force-with-lease`) — we will squash-merge on accept.

### Pull request checklist

- [ ] The library still builds with `python build_libtwofish.py` on Linux (and ideally one other OS).
- [ ] `python tests/test_roundtrip.py` passes.
- [ ] New public functions have docstrings.
- [ ] No third-party Python dependencies were added (this project is stdlib-only by design).
- [ ] No `.pka` files containing personal information were committed.
- [ ] README / CONTRIBUTING were updated if user-visible behavior changed.

### What we will and will not merge

We will gladly merge:

- Bug fixes, especially for new Packet Tracer versions.
- Build/portability improvements (Windows native, BSDs, alpine/musl).
- Additional examples and documentation.
- Performance improvements that do not change the public API.

We will probably not merge:

- Anything that adds a heavyweight Python dependency. The Twofish C file is the only native code we want to maintain.
- Features that exist solely to bypass Packet Tracer activity grading or licensing.
- Code without tests for non-trivial logic changes.

### Reporting security issues

Please do **not** open a public issue for a security vulnerability. Instead, open a private security advisory through GitHub's "Security" tab.

### Code of conduct

Be kind. Assume good faith. Disagreement is fine; personal attacks are not. We follow the spirit of the [Contributor Covenant](https://www.contributor-covenant.org/).

---

## License

This project is released under the [MIT License](./LICENSE).

The vendored Twofish implementation in [`vendor/twofish/`](./vendor/twofish/) is also MIT-licensed; see [`vendor/twofish/LICENSE`](./vendor/twofish/LICENSE).

## Credits

- Niels Ferguson — the original Twofish reference implementation.
- Mirco De Zorzi — [`pka2xml`](https://github.com/mircodz/pka2xml) and the [accompanying write-up](https://mircodezorzi.github.io/doc/reversing-packet-tracer/) that documented the file format.
- Arnaud Cheron — [`ptexplorer`](https://github.com/axcheron/ptexplorer), which decodes the older XOR-only Packet Tracer formats.
