"""Runs every rule set in test_yara.py through the real YARA as well, and fails on any disagreement.

    python tests/check_against_yara.py            # yara on PATH, or set YARA=/path/to/yara
"""
import os, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(root), str(root / "tests")]
import test_yara

YARA = os.environ.get("YARA") or shutil.which("yara") or sys.exit("check_against_yara: no yara binary (set YARA=...)")
orig = test_yara.hits
bad = []


checks = 0


def checked(rules, data, **ext):
    global checks
    checks += 1
    mine = orig(rules, data, **ext)
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "r.yar").write_text(rules)
        (Path(d) / "f.bin").write_bytes(data)
        defs = [a for k, v in ext.items() for a in ("-d", f"{k}={v}")]
        r = subprocess.run([YARA, "-w", *defs, str(Path(d) / "r.yar"), str(Path(d) / "f.bin")], capture_output=True, text=True)
        real = [l.split()[0] for l in r.stdout.splitlines()]
        if r.returncode or set(real) != set(mine):
            bad.append((rules[:200], mine, real, r.stderr.strip()))
    return mine


test_yara.hits = checked
result = unittest.main(module=test_yara, exit=False, argv=["x", "Strings", "Conditions", "PeModule"]).result
if not result.wasSuccessful():
    sys.exit(1)
for b in bad:
    print("DISAGREE\n", *b, sep="\n  ")
version = subprocess.run([YARA, "--version"], capture_output=True, text=True).stdout.strip()
print(f"{checks} rule sets compared with YARA {version}: {len(bad)} disagreement(s)")
sys.exit(1 if bad else 0)
