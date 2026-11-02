import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from helpers import RWX, RX, make_pe, random_bytes

from kirascan import cli
from kirascan.rules import load_builtin
from kirascan.scanner import scan_file

RULES = load_builtin()


class TempDir:
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name, data):
        p = self.dir / name
        p.write_bytes(data if isinstance(data, bytes) else data.encode())
        return p


class ScannerTest(TempDir, unittest.TestCase):
    def sources(self, res):
        return {f.source for f in res.findings}

    def test_plain_text_is_clean(self):
        res = scan_file(self.write("notes.txt", "meeting at 10, bring coffee\n" * 50), RULES)
        self.assertEqual((res.verdict, res.score, res.filetype), ("clean", 0, "text"))

    def test_injection_chain_in_raw_content(self):
        res = scan_file(self.write("tool.bin", b"\0VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0"), RULES)
        self.assertIn("rule:win-process-injection", self.sources(res))
        self.assertEqual(res.verdict, "low")

    def test_api_rules_use_pe_imports(self):
        chain = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
        importer = make_pe([(".text", RX, b"\x90" * 32)], imports={"KERNEL32.dll": chain})
        self.assertIn("rule:win-process-injection", self.sources(scan_file(self.write("inj.exe", importer), RULES)))
        # same names present only as strings (e.g. an export table) -> not a capability of this binary
        exporter = make_pe([(".text", RX, "\0".join(chain).encode())], imports={"ntdll.dll": ["NtClose"]})
        self.assertNotIn("rule:win-process-injection", self.sources(scan_file(self.write("k32.dll", exporter), RULES)))

    def test_behaviors_alone_never_malicious(self):
        apis = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection",
                "SetThreadContext", "ResumeThread", "GetAsyncKeyState", "SetWindowsHookExW", "IsDebuggerPresent",
                "CheckRemoteDebuggerPresent"]
        pe = make_pe([(".text", RX, b"\x90" * 32)], imports={"KERNEL32.dll": apis})
        res = scan_file(self.write("busy.exe", pe), RULES)
        self.assertGreater(sum(f.score for f in res.findings), 70)
        self.assertEqual(res.verdict, "suspicious")

    def test_packed_pe_is_malicious(self):
        pe = make_pe([("UPX0", RWX, b""), ("UPX1", RWX, random_bytes(16384)), (".rsrc", RX, b"UPX!")])
        res = scan_file(self.write("setup.exe", pe), RULES)
        titles = {f.title for f in res.findings}
        self.assertTrue({"Packer section names", "Writable + executable section", "High-entropy code section"} <= titles)
        self.assertEqual(res.verdict, "malicious")
        self.assertEqual(res.pe["machine"], "x64")

    def test_disguised_and_double_extension(self):
        pe = make_pe([(".text", RX, b"\x90" * 32)])
        self.assertIn("Executable disguised by extension",
                      {f.title for f in scan_file(self.write("cat.jpg", pe), RULES).findings})
        self.assertIn("Deceptive double extension",
                      {f.title for f in scan_file(self.write("invoice.pdf.exe", pe), RULES).findings})

    def test_reproducible_build_timestamp_is_ignored(self):
        pe = make_pe([(".text", RX, b"\x90" * 32)], timestamp=0xF0000000)
        self.assertEqual(scan_file(self.write("a.exe", pe), RULES).verdict, "clean")

    def test_embedded_executable(self):
        stub = b"This program cannot be run in DOS mode"
        res = scan_file(self.write("doc.bin", b"junk" * 10 + stub + b"more"), RULES)
        self.assertIn("Embedded executable", {f.title for f in res.findings})

    def test_compressed_formats_skip_entropy(self):
        res = scan_file(self.write("a.zip", b"PK\x03\x04" + random_bytes(8192)), RULES)
        self.assertNotIn("High entropy", {f.title for f in res.findings})

    def test_hashes(self):
        res = scan_file(self.write("abc.txt", "abc"), RULES)
        self.assertEqual(res.hashes["sha256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_score_capped(self):
        # keyword soup, not a working command — enough to fire rules without upsetting a real AV
        soup = b"-NoProfile\n-w hidden\nDownloadString\nFromBase64String\nvssadmin delete shadows\n"
        res = scan_file(self.write("invoice.pdf.exe", soup), RULES)
        self.assertEqual(res.score, 100)


class CLITest(TempDir, unittest.TestCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main([str(a) for a in argv])
        return code, out.getvalue(), err.getvalue()

    def test_exit_codes_and_json(self):
        self.write("clean.txt", "hello world, nothing to see")
        code, out, _ = self.run_cli(self.dir, "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["results"][0]["verdict"], "clean")

        self.write("notes.txt", "keywords: Net.WebClient DownloadFile -NoProfile -w hidden http://198.51.100.9/x")
        code, out, _ = self.run_cli(self.dir, "--no-color")
        self.assertEqual(code, 1)
        self.assertIn("SUSPICIOUS", out)

    def test_recursive(self):
        (self.dir / "sub").mkdir()
        self.write("sub/deep.txt", "hi there")
        self.assertEqual(json.loads(self.run_cli(self.dir, "--json")[1])["results"], [])
        self.assertEqual(len(json.loads(self.run_cli(self.dir, "-r", "--json")[1])["results"]), 1)

    def test_custom_rules(self):
        rules = self.write("mine.json", json.dumps([{"id": "kira", "strings": ["KIRA-MARKER"], "severity": "critical"}]))
        target = self.write("x.bin", b"..KIRA-MARKER..")
        code, out, _ = self.run_cli(target, "--rules", rules, "--no-builtin", "--json")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["results"][0]["findings"][0]["source"], "rule:kira")

    def test_errors(self):
        self.assertEqual(self.run_cli(self.dir / "missing.bin")[0], 3)
        bad = self.write("bad.json", "{not json")
        self.assertEqual(self.run_cli(self.write("x.txt", "x"), "--rules", bad)[0], 3)
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(self.run_cli(self.write("y.txt", "y"), "--vt")[0], 3)

    def test_virustotal_flag(self):
        target = self.write("z.txt", "plain text file")
        fake = {"malicious": 41, "suspicious": 0, "engines": 70, "label": "trojan.test"}
        with mock.patch.dict(os.environ, {"VT_API_KEY": "k"}), \
                mock.patch("kirascan.virustotal.lookup", return_value=fake):
            code, out, _ = self.run_cli(target, "--vt", "--json")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["results"][0]["virustotal"]["malicious"], 41)


if __name__ == "__main__":
    unittest.main()
