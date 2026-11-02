# kira-scan

**Zero-dependency static malware triage.** Point it at a file or a folder and get a scored verdict in milliseconds: hashes, entropy, PE structure, import-table capabilities, IOCs and signature rules. Pure Python standard library, so it runs on an air-gapped analysis box with nothing installed.

[![ci](https://github.com/njuj/kira-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/njuj/kira-scan/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%2B-00ff9c?labelColor=0b0f17)
![deps](https://img.shields.io/badge/dependencies-0-00ff9c?labelColor=0b0f17)
![license](https://img.shields.io/badge/license-MIT-00ff9c?labelColor=0b0f17)

```text
$ kira-scan notepad.exe mavinject.exe ClipUp.exe MRT.exe

 kira-scan v0.1.0  ·  4 file(s)  ·  10.67s

 • LOW         notepad.exe  score 5  ·  PE executable  ·  entropy 6.48
     └─ +5   Debugger detection checks — IsDebuggerPresent, OutputDebugString

 • LOW         mavinject.exe  score 35  ·  PE executable  ·  entropy 5.40
     ├─ +30  Remote process injection API chain — VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
     └─ +5   Debugger detection checks — IsDebuggerPresent, NtQueryInformationProcess, OutputDebugString

 ⚠ SUSPICIOUS  ClipUp.exe  score 40  ·  PE executable  ·  entropy 7.28
     ├─ +15  High entropy — 7.28 bits/byte, likely packed or encrypted
     ├─ +20  High-entropy code section — .text (7.45)
     └─ +5   Debugger detection checks — IsDebuggerPresent, OutputDebugString

 ⚠ SUSPICIOUS  MRT.exe  score 45  ·  PE executable  ·  entropy 7.05
     ├─ +25  Embedded executable — 15 DOS stub(s) inside the file
     ├─ +5   Debugger detection checks — IsDebuggerPresent, OutputDebugString
     └─ +15  Autorun registry key (persistence) — \CurrentVersion\Run, \CurrentVersion\RunOnce

 0 clean  ·  2 low  ·  2 suspicious  ·  0 malicious
```

> These are real Windows binaries, and the output is correct. `mavinject.exe` really is an injector: it is a known LOLBin, [MITRE T1218.013](https://attack.mitre.org/techniques/T1218/013/). `ClipUp.exe` ships with an obfuscated `.text` section, and `MRT.exe` (Microsoft's own removal tool) carries 15 embedded PE images. None of them comes out *malicious*, because capability alone is not intent (see [scoring](#scoring)).

## What it looks at

| Layer | Signals |
|---|---|
| **Identity** | MD5 / SHA-1 / SHA-256 (streamed, any file size), magic-byte file type |
| **Entropy** | Shannon entropy of the whole file and of every PE section. Skipped for formats that are compressed by design (zip, png, 7z…) |
| **PE structure** | own bounds-checked parser: sections, `W+X` sections, packer section names (UPX, Themida, VMProtect, MPRESS…), high-entropy code, import **and** export tables |
| **Capabilities** | JSON signature rules matched against the **import table** for PEs (e.g. injection, hollowing, keylogging, anti-debug) and against raw content for scripts and documents (PowerShell cradles, ransom notes, shadow-copy deletion, infostealer paths, webhook exfil…) |
| **Deception** | double extensions (`invoice.pdf.exe`), right-to-left override in names, PE bytes hiding behind a `.jpg`, executables embedded inside other files |
| **IOCs** | URLs, IPv4, e-mails, registry keys, `.onion`, bech32 BTC, from ASCII **and** UTF-16LE strings |
| **Intel** *(opt-in)* | VirusTotal v3 hash lookup. Only the SHA-256 leaves the machine, never the file |

## Install

```bash
pip install git+https://github.com/njuj/kira-scan
```

Or run it straight from a checkout, with nothing installed: `python -m kirascan <paths>`.

## Usage

```bash
kira-scan suspicious.exe                 # single file
kira-scan ~/Downloads -r                 # whole tree
kira-scan sample.bin -v                  # + hashes, PE sections, extracted IOCs
kira-scan samples/ -r --json > report.json
kira-scan drop.dll --rules my-rules/     # add your own rules
VT_API_KEY=... kira-scan sample.exe --vt # reputation lookup
```

**Exit codes** are built for pipelines: `0` clean/low · `1` suspicious · `2` malicious · `3` error.

```bash
kira-scan build/artifacts -r --no-color || echo "release blocked: scanner verdict $?"
```

## Scoring

Each finding has a weight and a **kind**:

| kind | examples | why it matters |
|---|---|---|
| `anomaly` | packed sections, `W+X`, disguised extension, embedded PE, shadow-copy deletion | rare in legitimate software |
| `behavior` | injection APIs, keyboard hooks, autorun keys, anti-debug | common in legitimate software too (debuggers, shells, AV, accessibility tools) |
| `intel` | VirusTotal detections | someone else already looked |

Behavior weight is **capped at 60**, so capabilities alone can make a file *suspicious* but never *malicious*.

`0` clean · `1–39` low · `40–69` suspicious · `70–100` malicious

Two design decisions that came out of testing against a real `System32`:

* **API rules read the import table, minus re-exports.** A naive string match flags `kernel32.dll` as an injector, because it *exports* `VirtualAllocEx`. Matching only what a binary imports and does not re-export makes `kernel32.dll` come out clean. Matching is also name-boundary aware: `SetWindowsHookEx` matches `SetWindowsHookExW`, but `GetAsyncKeyState` does not match `NtUserGetAsyncKeyState`.
* **No "compile timestamp in the future" check.** Reproducible builds (`/Brepro`) store a content hash in that field, which is why `explorer.exe` claims it was compiled in 2102.

Result on 699 Windows 11 binaries (every `System32\*.exe` and `System32\k*.dll`, including `kernel32`, `kernelbase` and the keyboard-layout DLLs, plus `user32.dll` and `explorer.exe`): **0 malicious, 2 suspicious** (the two above). Most of the 10 s in the demo goes on `MRT.exe`, which is a 230 MB file; kira-scan analyses the first 32 MB by default and streams the hashes over the whole file.

## Writing rules

```json
{
  "rules": [
    {
      "id": "my-c2-beacon",
      "description": "Known C2 URI pattern",
      "severity": "high",
      "strings": ["/gate.php", "/panel/connect"],
      "regex": ["User-Agent: Mozilla/4\\.0 \\(compatible; MSIE 6\\.0"],
      "condition": 2,
      "nocase": true
    }
  ]
}
```

| field | meaning |
|---|---|
| `strings` | literal text, matched as ASCII **and** UTF-16LE |
| `hex` | raw bytes, e.g. `"4D 5A 90 00"` |
| `regex` | Python regex over raw bytes |
| `condition` | `"any"`, `"all"`, or an integer N (N-of) |
| `scope` | `content` (default), or `imports` to match PE import names |
| `severity` | `low` 5 · `medium` 15 · `high` 30 · `critical` 60 (critical counts as an anomaly) |

Rule files are validated on load: bad hex, bad regex, impossible conditions and duplicate ids fail fast with a clear message.

## Layout

```
kirascan/
├── cli.py         argparse, exit codes, VirusTotal enrichment
├── scanner.py     heuristics + scoring model
├── pe.py          defensive PE parser (sections, imports, exports)
├── rules.py       signature engine + validation
├── iocs.py        ASCII/UTF-16 strings, IOC regexes
├── entropy.py     Shannon entropy
├── hashing.py     streamed MD5/SHA-1/SHA-256
├── report.py      terminal renderer (Unicode with ASCII fallback, NO_COLOR aware)
└── rules/builtin.json
tests/             unittest suite: synthetic PEs are built in memory, so the repo holds no live samples
```

```bash
python -m unittest discover -s tests -v
```

## Roadmap

- [ ] resolve dynamically loaded APIs (`GetProcAddress` + string table)
- [ ] ELF and Mach-O parsers
- [ ] optional `yara-python` backend for existing YARA rule sets
- [ ] archive recursion (zip / OOXML / 7z)
- [ ] HTML report

## Disclaimer

kira-scan is a **triage** tool: it tells you where to look first. It does not replace an AV/EDR or dynamic analysis. Handle live samples in an isolated VM.

---

<sub>built by <a href="https://github.com/njuj">kira</a> · trust nothing, verify everything</sub>
