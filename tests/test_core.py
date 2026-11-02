import time
import unittest

from helpers import RWX, RX, make_pe, random_bytes

from kirascan.entropy import shannon
from kirascan.iocs import extract_strings, find_iocs
from kirascan.pe import parse_pe
from kirascan.rules import RuleError, load_builtin, parse_rules


class EntropyTest(unittest.TestCase):
    def test_bounds(self):
        self.assertEqual(shannon(b""), 0.0)
        self.assertEqual(shannon(b"\x00" * 1000), 0.0)
        self.assertAlmostEqual(shannon(bytes(range(256))), 8.0)

    def test_random_is_high(self):
        self.assertGreater(shannon(random_bytes(65536)), 7.9)


class PETest(unittest.TestCase):
    def test_parses_sections(self):
        pe = parse_pe(make_pe([(".text", RX, b"\x90" * 64), ("UPX1", RWX, random_bytes(4096))]))
        self.assertEqual(pe.machine, "x64")
        self.assertEqual([s.name for s in pe.sections], [".text", "UPX1"])
        self.assertFalse(pe.sections[0].writable)
        self.assertEqual(pe.sections[1].flags, "RWX")
        self.assertGreater(pe.sections[1].entropy, 7.5)

    def test_rejects_non_pe(self):
        self.assertIsNone(parse_pe(b"hello world" * 10))
        self.assertIsNone(parse_pe(b"MZ" + b"\0" * 10))

    def test_survives_lying_headers(self):
        data = bytearray(make_pe([(".text", RX, b"\xcc" * 32)]))
        data[0x46:0x48] = (500).to_bytes(2, "little")  # claim 500 sections
        pe = parse_pe(bytes(data))
        self.assertLessEqual(len(pe.sections), 96)

    def test_parses_imports(self):
        pe = parse_pe(make_pe([(".text", RX, b"\x90" * 16)],
                              imports={"KERNEL32.dll": ["VirtualAllocEx", "Sleep"], "USER32.dll": ["MessageBoxW"]}))
        self.assertEqual(pe.imported_dlls, ["KERNEL32.dll", "USER32.dll"])
        self.assertEqual(pe.imports, ["VirtualAllocEx", "Sleep", "MessageBoxW"])

    def test_truncated_import_table(self):
        data = make_pe([(".text", RX, b"\x90" * 16)], imports={"A.dll": ["Func"]})
        self.assertEqual(parse_pe(data[:-12]).imports, [])

    def test_bad_e_lfanew(self):
        data = bytearray(make_pe([]))
        data[0x3C:0x40] = (0xFFFFFFF0).to_bytes(4, "little")
        self.assertIsNone(parse_pe(bytes(data)))


class RulesTest(unittest.TestCase):
    def rule(self, **kw):
        return parse_rules([{"id": "t", **kw}], "test")[0]

    def test_ascii_and_wide_strings(self):
        r = self.rule(strings=["EvilApi"])
        self.assertTrue(r.match(b"..EvilApi..", b""))
        wide = "EvilApi".encode("utf-16-le")
        self.assertTrue(r.match(wide, wide.lower()))

    def test_conditions(self):
        r = self.rule(strings=["a1", "b2", "c3"], condition=2)
        self.assertEqual(r.match(b"a1 c3", b""), ["a1", "c3"])
        self.assertEqual(r.match(b"a1", b""), [])
        self.assertEqual(self.rule(strings=["a1", "b2"], condition="all").condition, 2)

    def test_nocase(self):
        r = self.rule(strings=["DownloadString"], nocase=True)
        data = b"x.downloadstring(y)"
        self.assertTrue(r.match(data, data.lower()))

    def test_hex_and_regex(self):
        self.assertTrue(self.rule(hex=["DE AD BE EF"]).match(b"\x00\xde\xad\xbe\xef", b""))
        self.assertTrue(self.rule(regex=[r"https?://\d+\.\d+\.\d+\.\d+/"]).match(b"get http://10.0.0.1/a", b""))

    def test_validation(self):
        for bad in ({"strings": ["x"], "severity": "spicy"}, {"hex": ["zz"]}, {"regex": ["("]}, {},
                    {"strings": ["x"], "condition": 5}, {"strings": ["x"], "condition": True},
                    {"strings": ["x"], "scope": "exports"}):
            with self.subTest(bad=bad), self.assertRaises(RuleError):
                self.rule(**bad)
        with self.assertRaises(RuleError):
            parse_rules([{"id": "a", "strings": ["x"]}, {"id": "a", "strings": ["y"]}], "dupes")

    def test_builtin_rules_load(self):
        rules = load_builtin()
        self.assertGreaterEqual(len(rules), 10)
        self.assertEqual(len({r.id for r in rules}), len(rules))


class IOCTest(unittest.TestCase):
    def test_extracts_wide_strings(self):
        self.assertIn("hidden", extract_strings(b"\x00\x01" + "hidden".encode("utf-16-le") + b"\xff"))

    def test_indicators(self):
        text = ("beacon to http://203.0.113.7:8080/gate.php, mail ops@example.org, "
                r"persist HKCU\Software\Microsoft\Windows\CurrentVersion\Run ok")
        iocs = find_iocs([text])
        self.assertEqual(iocs["urls"], ["http://203.0.113.7:8080/gate.php"])
        self.assertEqual(iocs["ipv4"], ["203.0.113.7"])
        self.assertEqual(iocs["emails"], ["ops@example.org"])
        self.assertEqual(iocs["registry"], [r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"])

    def test_ipv4_bounds(self):
        self.assertNotIn("ipv4", find_iocs(["version 999.1.1.1 and 1.2.3"]))

    def test_version_numbers_are_not_ips(self):
        self.assertNotIn("ipv4", find_iocs(["FileVersion 6.0.0.0 / 5.1.0.0"]))


if __name__ == "__main__":
    unittest.main()
