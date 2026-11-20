"""A YARA engine in pure Python, for the rules people already have.

It reads the YARA language: text, hex and regex strings with their modifiers (nocase, wide, ascii,
fullword, xor, base64, private), the condition language (boolean and arithmetic operators,
``N of them``, ``$a at``/``in``, ``#a``, ``@a[i]``, ``!a[i]``, ``uint16(0)``, string loops and
integer loops, rule references, global and private rules) and the parts of the ``pe``, ``math`` and
``hash`` modules that rules lean on (``pe.imphash()``, ``pe.imports()``, ``pe.exports()``, sections,
header fields; ``math.entropy()``; ``hash.md5()``).

A rule that needs something it does not implement (``pe.signatures``, resources, version info,
another module, ``include``) is *skipped with the reason*, never evaluated wrongly.
"""

from __future__ import annotations

import base64
import hashlib
import math
import re
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from .pe import parse_pe


class YaraError(ValueError):
    """Text that is not valid YARA (or that this engine does not implement)."""


class _Undefined:
    """YARA's undefined value: anything computed from it is undefined, and it is never true."""
    __slots__ = ()

    def __bool__(self):
        return False

    def __repr__(self):
        return "UNDEFINED"


UNDEF = _Undefined()
MAX_MATCHES = 10_000
GRAM_LIMIT = 64 << 20
# shortcut: catches the classic catastrophic shapes like (a+)+ or (\w*\s?)*; YARA's own engine needs no such guard
NESTED_REPEAT = re.compile(r"\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)[+*{]")
STR_MODS = {"nocase", "wide", "ascii", "fullword", "private", "xor", "base64", "base64wide"}


# ── reading the source ─────────────────────────────────────────────────────────

class _Src:
    KEYWORDS_END = re.compile(r"[A-Za-z0-9_]")

    def __init__(self, text: str, name: str):
        self.s, self.i, self.name = text, 0, name

    def err(self, msg):
        line = self.s.count("\n", 0, self.i) + 1
        raise YaraError(f"{self.name}:{line}: {msg}")

    def ws(self):
        s = self.s
        while self.i < len(s):
            c = s[self.i]
            if c in " \t\r\n\f\v":
                self.i += 1
            elif s.startswith("//", self.i):
                j = s.find("\n", self.i)
                self.i = len(s) if j < 0 else j
            elif s.startswith("/*", self.i):
                j = s.find("*/", self.i + 2)
                self.i = len(s) if j < 0 else j + 2
            else:
                return

    def peek(self, word: str) -> bool:
        self.ws()
        if not self.s.startswith(word, self.i):
            return False
        end = self.i + len(word)
        return not (word[-1].isalnum() or word[-1] == "_") or end >= len(self.s) or not self.KEYWORDS_END.match(self.s[end])

    def take(self, word: str) -> bool:
        if self.peek(word):
            self.i += len(word)
            return True
        return False

    def expect(self, word: str):
        if not self.take(word):
            self.err(f"expected {word!r}")

    def ident(self) -> str:
        self.ws()
        m = re.compile(r"[A-Za-z_][A-Za-z0-9_]*").match(self.s, self.i)
        if not m:
            self.err("expected an identifier")
        self.i = m.end()
        return m.group()

    def string(self) -> bytes:
        """A double-quoted YARA string, escapes resolved, as bytes."""
        self.ws()
        if self.s[self.i:self.i + 1] != '"':
            self.err("expected a string")
        out, i, s = bytearray(), self.i + 1, self.s
        while i < len(s) and s[i] != '"':
            c = s[i]
            if c == "\\" and i + 1 < len(s):
                e = s[i + 1]
                if e == "x" and re.match(r"[0-9A-Fa-f]{2}", s[i + 2:i + 4]):
                    out.append(int(s[i + 2:i + 4], 16))
                    i += 4
                    continue
                out += {"n": b"\n", "t": b"\t", "r": b"\r", '"': b'"', "\\": b"\\"}.get(e, ("\\" + e).encode("utf-8"))
                i += 2
                continue
            if c == "\n":
                self.err("newline inside a string")
            out += c.encode("utf-8")
            i += 1
        if i >= len(s):
            self.err("unterminated string")
        self.i = i + 1
        return bytes(out)

    def regex(self) -> tuple[str, str]:
        """/pattern/flags → (pattern, flags)."""
        self.ws()
        if self.s[self.i:self.i + 1] != "/":
            self.err("expected a regular expression")
        i, s = self.i + 1, self.s
        while i < len(s) and s[i] != "/":
            if s[i] == "\\":
                i += 1
            elif s[i] == "\n":
                self.err("newline inside a regular expression")
            i += 1
        pattern = s[self.i + 1:i]
        j = i + 1
        while j < len(s) and s[j] in "is":
            j += 1
        self.i = j
        return pattern, s[i + 1:j]


# ── strings ───────────────────────────────────────────────────────────────────

def _hex_to_regex(body: str) -> tuple[bytes, bytes]:
    """A YARA hex string as a bytes regex, plus its longest fixed run (a cheap pre-check)."""
    toks = re.findall(r"~?[0-9A-Fa-f?]{2}|\[[^\]]*\]|[()|]", re.sub(r"//[^\n]*|/\*.*?\*/", "", body, flags=re.S))
    rx, run, best, depth = [], b"", b"", 0
    for t in toks:
        if t in "()|":
            depth += t == "("
            depth -= t == ")"
            rx.append({"(": "(?:", ")": ")", "|": "|"}[t])
            run = b""
            continue
        if t.startswith("["):
            m = re.fullmatch(r"\[\s*(\d*)\s*(-?)\s*(\d*)\s*\]", t)
            if not m:
                raise YaraError(f"bad jump {t}")
            lo, dash, hi = m.groups()
            rx.append(".{%s,%s}?" % (lo or "0", hi) if dash else ".{%s}" % (lo or "0"))
            run = b""
            continue
        neg, h = t.startswith("~"), t.lstrip("~")
        if h == "??":
            rx.append(".")
            run = b""
        elif "?" in h:
            vals = [int(h.replace("?", d), 16) for d in "0123456789ABCDEF"]
            rx.append("[%s%s]" % ("^" if neg else "", "".join("\\x%02x" % v for v in vals)))
            run = b""
        else:
            v = int(h, 16)
            rx.append("[^\\x%02x]" % v if neg else re.escape(bytes([v])).decode("latin-1"))
            if neg:
                run = b""
            elif depth == 0:
                run += bytes([v])
                best = max(best, run, key=len)
    if not rx:
        raise YaraError("empty hex string")
    return "".join(rx).encode("latin-1"), best


def _b64_forms(text: bytes) -> list[bytes]:
    """The three base64 renderings of `text` at offsets 0, 1, 2, trimmed as YARA trims them."""
    out = []
    for pad, cut_left in ((b"", 0), (b"\0", 2), (b"\0\0", 3)):
        enc = base64.b64encode(pad + text).rstrip(b"=")
        enc = enc[cut_left:]
        rem = (len(pad) + len(text)) % 3
        if rem:                                # the last character also depends on what follows
            enc = enc[:-1]
        if enc:
            out.append(enc)
    return out


@dataclass
class YString:
    name: str
    kind: str                       # text | hex | regex
    literals: list = field(default_factory=list)    # [(bytes, nocase)] for text
    regex: re.Pattern | None = None
    atom: bytes = b""
    fullword: bool = False
    wide: bool = False
    private: bool = False

    def find(self, ctx) -> list[tuple[int, int]]:
        hits = []
        if self.regex is not None:
            if self.atom and not ctx.may_contain(self.atom, False):
                return hits
            for m in self.regex.finditer(ctx.data):
                hits.append((m.start(), m.end() - m.start()))
                if len(hits) >= MAX_MATCHES:
                    break
        else:
            for needle, nocase in self.literals:
                if not ctx.may_contain(needle, nocase):
                    continue
                hay = ctx.lower if nocase else ctx.data
                i = hay.find(needle)
                while i >= 0 and len(hits) < MAX_MATCHES:
                    hits.append((i, len(needle)))
                    i = hay.find(needle, i + 1)
        if self.fullword:
            hits = [h for h in hits if self._word(ctx.data, *h)]
        return sorted(set(hits))

    def _word(self, data: bytes, off: int, n: int) -> bool:
        step = 2 if self.wide and n > 1 and data[off + 1] == 0 else 1
        before = data[off - step:off] if off >= step else b""
        after = data[off + n:off + n + step]
        isw = lambda b: bool(b) and b[:1].isalnum() and (step == 1 or b[1:2] == b"\0")
        return not isw(before) and not isw(after)


def _compile_string(src: _Src, name: str) -> YString:
    src.ws()
    c = src.s[src.i:src.i + 1]
    if c == '"':
        text, kind = src.string(), "text"
    elif c == "{":
        end = _hex_end(src.s, src.i)
        if end < 0:
            src.err("unterminated hex string")
        body, src.i, kind = src.s[src.i + 1:end], end + 1, "hex"
    elif c == "/":
        (pattern, flags), kind = src.regex(), "regex"
    else:
        src.err("expected a string value")
    mods, xor_range, b64_alpha = set(), None, None
    while True:
        src.ws()
        m = re.compile(r"(nocase|wide|ascii|fullword|private|xor|base64wide|base64)\b").match(src.s, src.i)
        if not m:
            break
        src.i = m.end()
        mods.add(m.group(1))
        if m.group(1) == "xor" and src.take("("):
            lo = hi = _int(_number(src))
            if src.take("-"):
                hi = _int(_number(src))
            src.expect(")")
            xor_range = (lo, hi)
        elif m.group(1).startswith("base64") and src.take("("):
            b64_alpha = src.string()
            src.expect(")")
    ys = YString(name, kind, fullword="fullword" in mods, wide="wide" in mods, private="private" in mods)
    if kind == "hex":
        rx, ys.atom = _hex_to_regex(body)
        ys.regex = re.compile(rx, re.S)
        return ys
    if kind == "regex":
        rx = _yara_regex(pattern)
        if NESTED_REPEAT.search(rx):
            raise YaraError("regular expression with a repeat inside a repeat (it can take forever in Python's engine)")
        if "wide" in mods:
            rx = _widen(rx) if "ascii" not in mods else f"(?:{rx})|(?:{_widen(rx)})"
        try:
            ys.regex = re.compile(rx.encode("latin-1"),
                                  (re.I if "i" in flags or "nocase" in mods else 0) | (re.S if "s" in flags else 0))
        except (re.error, UnicodeEncodeError, OverflowError) as e:
            raise YaraError(f"regular expression this engine cannot read: {e}") from None
        ys.atom = _regex_atom(pattern) if not ({"i"} & set(flags) or {"nocase", "wide"} & mods) else b""
        return ys
    if b64_alpha is not None:
        raise YaraError("custom base64 alphabets are not supported")
    nocase = "nocase" in mods
    forms = []
    if "ascii" in mods or "wide" not in mods:
        forms.append(text)
    if "wide" in mods:
        forms.append(b"".join(bytes([b, 0]) for b in text))
    if "base64" in mods or "base64wide" in mods:
        encoded = [e for t in ([text]) for e in _b64_forms(t)]
        forms = []
        if "base64" in mods:
            forms += encoded
        if "base64wide" in mods:
            forms += [b"".join(bytes([b, 0]) for b in e) for e in encoded]
    if "xor" in mods:
        lo, hi = xor_range or (0, 255)
        forms = [bytes(b ^ k for b in f) for f in forms for k in range(lo, hi + 1)]
    ys.literals = [(f.lower() if nocase else f, nocase) for f in dict.fromkeys(forms)]
    return ys


def _yara_regex(p: str) -> str:
    # shortcut: YARA's regex dialect is close to Python's; only the differences seen in real rules are mapped
    return p.replace("\\/", "/")


def _hex_end(s: str, i: int) -> int:
    """Index of the } closing a hex string, skipping comments inside it (they may hold a brace)."""
    while i < len(s):
        if s.startswith("//", i):
            i = s.find("\n", i)
            i = len(s) if i < 0 else i
        elif s.startswith("/*", i):
            i = s.find("*/", i)
            i = len(s) if i < 0 else i + 2
        elif s[i] == "}":
            return i
        else:
            i += 1
    return -1


def _widen(p: str) -> str:
    """A regex for the UTF-16LE form of what `p` matches: every character it consumes is followed by a zero byte."""
    out, i = [], 0
    while i < len(p):
        c = p[i]
        if c == "\\" and i + 1 < len(p):
            e = p[i + 1]
            n = 4 if e == "x" else 2
            atom, i = p[i:i + n], i + n
            out.append(atom if e in "bBAZ" else f"(?:{atom}\x00)")
        elif c == "[":
            j = i + 1 + (p[i + 1:i + 2] == "^")
            j += p[j:j + 1] == "]"
            while j < len(p) and p[j] != "]":
                j += 2 if p[j] == "\\" else 1
            out.append(f"(?:{p[i:j + 1]}\x00)")
            i = j + 1
        elif c == "(" and p[i + 1:i + 2] == "?":
            out.append(p[i:i + 3])
            i += 3
        elif c in "()|^$*+?":
            out.append(c)
            i += 1
        elif c == "{" and re.match(r"\{\d*,?\d*\}", p[i:]):
            m = re.match(r"\{\d*,?\d*\}", p[i:])
            out.append(m.group())
            i += m.end()
        else:
            out.append(f"(?:{re.escape(c)}\x00)" if c != "." else "(?:.\x00)")
            i += 1
    return "".join(out)


def _regex_atom(p: str) -> bytes:
    """A literal that every match must contain: the longest run of plain characters outside groups."""
    best, run, depth, i = "", "", 0, 0
    while i < len(p):
        c = p[i]
        if c == "\\" and i + 1 < len(p):
            e = p[i + 1]
            lit = e if not e.isalnum() else None
            if e == "x" and re.match(r"[0-9A-Fa-f]{2}", p[i + 2:i + 4]):
                lit, i = chr(int(p[i + 2:i + 4], 16)), i + 2
            i += 2
            if lit is not None and depth == 0 and not (i < len(p) and p[i] in "?*{"):
                run += lit
                best = max(best, run, key=len)
            else:
                run = ""
            continue
        if c in "([":
            depth += 1
            run = ""
            if c == "[":
                j = p.find("]", i + 2)
                i = len(p) if j < 0 else j + 1
                depth -= 1
                continue
        elif c == ")":
            depth -= 1
            run = ""
        elif c in ".^$|+":
            run = "" if c != "+" else run
            if c == "|":
                return b""                       # top-level alternation: no single required literal
        elif c in "?*{":
            run = run[:-1]
        elif depth == 0:
            run += c
            best = max(best, run, key=len)
        i += 1
    return best.encode("latin-1") if len(best) >= 3 else b""


def _number(src: _Src) -> str:
    src.ws()
    m = re.compile(r"0x[0-9A-Fa-f]+|0o[0-7]+|\d+").match(src.s, src.i)
    if not m:
        src.err("expected a number")
    src.i = m.end()
    return m.group()


def _int(v: str) -> int:
    return int(v[2:], 16) if v[:2] in ("0x", "0X") else int(v[2:], 8) if v[:2] == "0o" else int(v, 10)


# ── conditions: parsed into nested tuples ─────────────────────────────────────

_TOKEN = re.compile(r"""
    (?P<num>0x[0-9A-Fa-f]+|0o[0-7]+|\d+(?:\.\d+)?(?:KB|MB)?)
  | (?P<str>")
  | (?P<rx>/)
  | (?P<sid>(?:[$#@]|!(?!=))[A-Za-z0-9_]*\*?)
  | (?P<id>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op>\.\.|==|!=|<=|>=|<<|>>|[<>()\[\],.+\-*\\%&|^~:=])
""", re.X)


class _Cond:
    def __init__(self, src: _Src, strings: dict, rules: dict, modules: set, externals: dict):
        self.src, self.strings, self.rules, self.modules, self.externals = src, strings, rules, modules, externals
        self.loopvars: list[set] = []
        self.anon_string = 0          # inside "for .. of": $ means the current string

    def tok(self, peek=False):
        s = self.src
        s.ws()
        if s.i >= len(s.s) or s.s[s.i] == "}":
            return ("end", "}")
        if s.s[s.i] == '"':
            if peek:
                return ("str", None)
            return ("str", s.string())
        if s.s[s.i] == "/":
            if peek:
                return ("rx", None)
            pattern, flags = s.regex()
            try:
                return ("rx", re.compile(_yara_regex(pattern).encode("latin-1"), (re.I if "i" in flags else 0) | (re.S if "s" in flags else 0)))
            except re.error as e:
                s.err(f"bad regular expression: {e}")
        m = _TOKEN.match(s.s, s.i)
        if not m:
            s.err(f"unexpected character {s.s[s.i]!r}")
        if not peek:
            s.i = m.end()
        kind = m.lastgroup
        return (kind, m.group())

    def at(self, *values) -> bool:
        k, v = self.tok(peek=True)
        return v in values and k in ("op", "id")

    def take(self, *values) -> str | None:
        if self.at(*values):
            return self.tok()[1]
        return None

    def expect(self, value):
        if not self.take(value):
            k, v = self.tok(peek=True)
            self.src.err(f"expected {value!r}, found {v!r}")

    # precedence, lowest first
    def expr(self):
        node = self.and_()
        while self.take("or"):
            node = ("or", node, self.and_())
        return node

    def and_(self):
        node = self.not_()
        while self.take("and"):
            node = ("and", node, self.not_())
        return node

    def not_(self):
        if self.take("not"):
            return ("not", self.not_())
        if self.take("defined"):
            return ("defined", self.not_())
        return self.rel()

    RELS = ("==", "!=", "<=", ">=", "<", ">", "contains", "icontains", "startswith", "istartswith",
            "endswith", "iendswith", "iequals", "matches")

    def rel(self):
        node = self.bitor()
        while True:
            op = self.take(*self.RELS)
            if not op:
                return node
            node = ("rel", op, node, self.tok()[1] if op == "matches" and self.tok(peek=True)[0] == "rx" else self.bitor())

    def _binary(self, nxt, ops):
        node = nxt()
        while True:
            op = self.take(*ops)
            if not op:
                return node
            node = ("bin", op, node, nxt())

    def bitor(self):
        return self._binary(self.bitxor, ("|",))

    def bitxor(self):
        return self._binary(self.bitand, ("^",))

    def bitand(self):
        return self._binary(self.shift, ("&",))

    def shift(self):
        return self._binary(self.add, ("<<", ">>"))

    def add(self):
        return self._binary(self.mul, ("+", "-"))

    def mul(self):
        return self._binary(self.unary, ("*", "\\", "%"))

    def unary(self):
        if self.take("-"):
            return ("neg", self.unary())
        if self.take("~"):
            return ("inv", self.unary())
        return self.primary()

    def range_(self):
        self.expect("(")
        lo = self.expr()
        self.expect("..")
        hi = self.expr()
        self.expect(")")
        return (lo, hi)

    def string_set(self):
        if self.take("them"):
            return list(self.strings)
        self.expect("(")
        names = []
        while True:
            k, v = self.tok()
            if k != "sid" or not v.startswith("$"):
                self.src.err("expected a string identifier in the set")
            if v == "$*" or v == "$":
                names += list(self.strings)
            elif v.endswith("*"):
                names += [n for n in self.strings if n.startswith(v[:-1])]
            elif v in self.strings:
                names.append(v)
            else:
                self.src.err(f"undefined string {v}")
            if not self.take(","):
                break
        self.expect(")")
        return names

    def quantifier(self, first):
        """any | all | none | <expr> [%] — `first` is the already-parsed leading node or keyword."""
        if first in ("any", "all", "none"):
            return ("kw", first)
        if self.take("%"):
            return ("pct", first)
        return ("n", first)

    def primary(self):
        k, v = self.tok()
        if k == "num":
            mult = 1024 if v.endswith("KB") else 1024 * 1024 if v.endswith("MB") else 1
            v = v[:-2] if mult > 1 else v
            n = float(v) if "." in v else _int(v)
            return self._maybe_of(("lit", n * mult))
        if k == "str":
            return ("lit", v.decode("latin-1"))
        if k == "rx":
            return ("lit", v)
        if k == "sid":
            return self.string_ref(v)
        if v == "(":
            node = self.expr()
            self.expect(")")
            return self._maybe_of(node)
        if v in ("true", "false"):
            return ("lit", v == "true")
        if v in ("filesize",):
            return ("filesize",)
        if v == "entrypoint":
            return ("attr", ("module", "pe"), "entry_point")
        if v in ("any", "all", "none"):
            return self.of(("kw", v))
        if v == "for":
            return self.for_()
        m = re.fullmatch(r"(u?int)(8|16|32)(be)?", v or "")
        if m:
            self.expect("(")
            off = self.expr()
            self.expect(")")
            return ("int", m.group(1) == "uint", int(m.group(2)), bool(m.group(3)), off)
        if k == "id":
            for scope in reversed(self.loopvars):
                if v in scope:
                    return self.postfix(("var", v))
            if v in self.modules:
                return self.postfix(("module", v))
            if v in ("pe", "math", "hash", "cuckoo", "magic", "dotnet", "elf", "time", "console", "string"):
                self.src.err(f"module {v!r} used without import, or not supported")
            if v in self.rules:
                return ("rule", v)
            if v in self.externals:
                return ("ext", v, self.externals[v])
            self.src.err(f"undefined identifier {v!r}")
        self.src.err(f"unexpected {v!r}")

    def _maybe_of(self, node):
        if self.at("of"):
            return self.of(self.quantifier(node))
        if self.at("%"):
            self.take("%")
            if self.at("of"):
                return self.of(("pct", node))
            self.src.err("expected 'of' after a percentage")
        return node

    def of(self, quant):
        self.expect("of")
        if self.at("("):
            save = self.src.i
            self.tok()
            k, v = self.tok(peek=True)
            self.src.i = save
            if k != "sid":
                self.src.err("sets of rules are not supported")
        names = self.string_set()
        if self.take("in"):
            return ("of", quant, names, ("in", self.range_()))
        if self.take("at"):
            return ("of", quant, names, ("at", self.bitor()))
        return ("of", quant, names, None)

    def for_(self):
        k, v = self.tok()
        if v in ("any", "all", "none"):
            quant = ("kw", v)
        elif k == "num":
            quant = ("n", ("lit", _int(v)))
            if self.take("%"):
                quant = ("pct", ("lit", _int(v)))
        else:
            self.src.err("unsupported loop quantifier")
        if self.take("of"):
            names = self.string_set()
            self.expect(":")
            self.anon_string += 1
            self.expect("(")
            body = self.expr()
            self.expect(")")
            self.anon_string -= 1
            return ("forof", quant, names, body)
        ids = [self.src.ident()]
        while self.take(","):
            ids.append(self.src.ident())
        self.expect("in")
        if self.at("("):
            self.expect("(")
            first = self.expr()
            if self.take(".."):
                hi = self.expr()
                self.expect(")")
                it = ("range", first, hi)
            else:
                items = [first]
                while self.take(","):
                    items.append(self.expr())
                self.expect(")")
                it = ("enum", items)
        else:
            it = ("iter", self.primary())
        self.expect(":")
        self.loopvars.append(set(ids))
        self.expect("(")
        body = self.expr()
        self.expect(")")
        self.loopvars.pop()
        return ("forin", quant, ids, it, body)

    def string_ref(self, v):
        sig, name = v[0], "$" + v[1:]
        if v.endswith("*"):
            self.src.err("a wildcard string name only works inside a set")
        if name == "$":
            if not self.anon_string:
                self.src.err("$ outside a string loop")
        elif name not in self.strings:
            self.src.err(f"undefined string {name}")
        if sig == "$":
            if self.take("at"):
                return ("str_at", name, self.bitor())
            if self.take("in"):
                return ("str_in", name, self.range_())
            return ("str", name)
        if sig == "#":
            if self.take("in"):
                return ("count_in", name, self.range_())
            return ("count", name)
        idx = ("lit", 1)
        if self.take("["):
            idx = self.expr()
            self.expect("]")
        return ("offset" if sig == "@" else "length", name, idx)

    def postfix(self, node):
        while True:
            if self.take("."):
                node = ("attr", node, self.src.ident())
            elif self.take("["):
                if self.tok(peek=True)[0] == "str":
                    key = ("lit", self.tok()[1].decode("latin-1"))
                else:
                    key = self.expr()
                self.expect("]")
                node = ("index", node, key)
            elif self.at("("):
                self.expect("(")
                args = []
                if not self.take(")"):
                    while True:
                        k, v = self.tok(peek=True)
                        args.append(("lit", self.tok()[1]) if k == "rx" else self.expr())
                        if not self.take(","):
                            break
                    self.expect(")")
                if node == ("attr", ("module", "pe"), "imports") and len(args) == 2:
                    is_rx = [a[0] == "lit" and isinstance(a[1], re.Pattern) for a in args]
                    if is_rx[0] != is_rx[1] and not (args[1][0] == "lit" and isinstance(args[1][1], int)):
                        self.src.err("pe.imports takes two strings or two regular expressions, not one of each")
                node = ("call", node, args)
            else:
                _check_module_path(self.src, node)
                return node


SUPPORTED = {
    "pe": {"is_pe", "is_dll", "is_32bit", "is_64bit", "imphash", "imports", "exports", "number_of_exports",
           "number_of_imports", "number_of_sections", "sections", "section_index", "timestamp", "machine",
           "characteristics", "subsystem", "entry_point", "overlay", "dll_name", "opthdr_magic", "linker_version",
           "MACHINE_I386", "MACHINE_AMD64", "MACHINE_ARM64", "MACHINE_ARM", "MACHINE_ARMNT", "DLL", "EXECUTABLE_IMAGE",
           "SUBSYSTEM_NATIVE", "SUBSYSTEM_WINDOWS_GUI", "SUBSYSTEM_WINDOWS_CUI", "SECTION_MEM_EXECUTE",
           "SECTION_MEM_READ", "SECTION_MEM_WRITE", "SECTION_CNT_CODE", "SECTION_CNT_INITIALIZED_DATA",
           "RELOCS_STRIPPED", "LARGE_ADDRESS_AWARE", "SYSTEM", "IMAGE_FILE_MACHINE_I386", "IMAGE_FILE_MACHINE_AMD64"},
    "math": {"entropy", "mean", "deviation", "in_range", "to_number", "count", "percentage", "abs", "min", "max"},
    "hash": {"md5", "sha1", "sha256", "crc32", "checksum32"},
}


def _check_module_path(src, node):
    path = []
    while node[0] in ("attr", "index", "call"):
        if node[0] == "attr":
            path.append(node[2])
        node = node[1]
    if node[0] == "module" and path:
        top = path[-1]
        if top not in SUPPORTED.get(node[1], ()):
            src.err(f"{node[1]}.{top} is not supported")


# ── rules ─────────────────────────────────────────────────────────────────────

@dataclass
class YaraRule:
    name: str
    tags: tuple
    meta: dict
    strings: dict
    condition: tuple
    private: bool = False
    is_global: bool = False
    namespace: str = ""


@dataclass
class Match:
    rule: str
    tags: tuple
    meta: dict
    strings: list            # [(name, offset, data excerpt)]
    namespace: str = ""


@dataclass
class RuleSet:
    rules: list = field(default_factory=list)
    skipped: list = field(default_factory=list)     # [(source, rule name or "", reason)]


def compile_text(text: str, source: str = "<rules>", externals: dict | None = None, into: RuleSet | None = None) -> RuleSet:
    externals = dict(externals or {})
    rs = into or RuleSet()
    src = _Src(text, source)
    modules: set = set()
    known = {r.name: r for r in rs.rules if r.namespace == source}
    while True:
        src.ws()
        if src.i >= len(src.s):
            return rs
        if src.take("import"):
            mod = src.string().decode()
            if mod in SUPPORTED:
                modules.add(mod)
            continue
        if src.take("include"):
            rs.skipped.append((source, "", f"include {src.string().decode()!r} is not followed"))
            continue
        start = src.i
        try:
            rule = _rule(src, modules, known, externals, source)
            known[rule.name] = rule
            rs.rules.append(rule)
        except (YaraError, ValueError, IndexError, RecursionError) as e:
            name = re.match(r"\s*(?:(?:private|global)\s+)*rule\s+(\w+)", src.s[start:start + 300])
            rs.skipped.append((source, name.group(1) if name else "", str(e).split(": ", 1)[-1]))
            nxt = re.compile(r"\n\s*(?:(?:(?:private|global)\s+)*rule\s+\w+|include\b|import\b)").search(src.s, max(src.i, start + 1))
            src.i = nxt.start() if nxt else len(src.s)


def _rule(src, modules, known, externals, source) -> YaraRule:
    private = is_global = False
    while True:
        if src.take("private"):
            private = True
        elif src.take("global"):
            is_global = True
        else:
            break
    src.expect("rule")
    name = src.ident()
    tags = []
    if src.take(":"):
        while not src.peek("{"):
            tags.append(src.ident())
    src.expect("{")
    meta, strings, cond = {}, {}, None
    if src.take("meta"):
        src.expect(":")
        while not (src.peek("strings") or src.peek("condition")):
            key = src.ident()
            src.expect("=")
            src.ws()
            if src.s[src.i] == '"':
                val = src.string().decode("utf-8", "replace")
            else:
                m = re.compile(r"-?\d+|true|false").match(src.s, src.i)
                if not m:
                    src.err("bad meta value")
                src.i = m.end()
                val = {"true": True, "false": False}.get(m.group(), None)
                val = int(m.group()) if val is None else val
            meta.setdefault(key, val)
    if src.take("strings"):
        src.expect(":")
        anon = 0
        while not src.peek("condition"):
            src.ws()
            m = re.compile(r"\$[A-Za-z0-9_]*").match(src.s, src.i)
            if not m:
                src.err("expected a string identifier")
            src.i = m.end()
            sname = m.group()
            if sname == "$":
                anon += 1
                sname = f"$__anon{anon}"
            src.expect("=")
            strings[sname] = _compile_string(src, sname)
    src.expect("condition")
    src.expect(":")
    cond = _Cond(src, strings, known, modules, externals).expr()
    src.expect("}")
    return YaraRule(name, tuple(tags), meta, strings, cond, private, is_global, source)


def load_rules(paths, externals: dict | None = None) -> RuleSet:
    rs = RuleSet()
    for p in paths:
        p = Path(p)
        files = sorted(f for f in p.rglob("*") if f.suffix.lower() in (".yar", ".yara")) if p.is_dir() else [p]
        for f in files:
            compile_text(f.read_text(encoding="utf-8", errors="replace"), str(f), externals, rs)
    return rs


# ── evaluation ────────────────────────────────────────────────────────────────

class _Ctx:
    def __init__(self, data: bytes):
        self.data = data
        self.lower = data.lower()
        self.cache: dict = {}
        self._pe = None
        self.results: dict = {}
        self._grams: dict = {}
        self.externals: dict = {}

    def may_contain(self, needle: bytes, nocase: bool) -> bool:
        """A fast 'no': every 4-byte window of the file goes in a set once, then each string costs one lookup."""
        if len(needle) < 4 or len(self.data) > GRAM_LIMIT:
            return True
        grams = self._grams.get(nocase)
        if grams is None:
            hay = self.lower if nocase else self.data
            grams = self._grams[nocase] = {hay[i:i + 4] for i in range(len(hay) - 3)}
        return needle[:4] in grams and needle[-4:] in grams

    def matches(self, rule: YaraRule, name: str):
        key = (id(rule), name)
        if key not in self.cache:
            self.cache[key] = rule.strings[name].find(self)
        return self.cache[key]

    @property
    def pe(self):
        if self._pe is None:
            self._pe = _PE(self.data)
        return self._pe


def _num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else (int(v) if isinstance(v, bool) else UNDEF)


def _eval(node, ctx: _Ctx, rule: YaraRule, env: dict):
    op = node[0]
    if op == "lit":
        return node[1]
    if op == "and":
        a = _eval(node[1], ctx, rule, env)
        return bool(a) and bool(_eval(node[2], ctx, rule, env))
    if op == "or":
        return bool(_eval(node[1], ctx, rule, env)) or bool(_eval(node[2], ctx, rule, env))
    if op == "not":
        v = _eval(node[1], ctx, rule, env)
        return UNDEF if v is UNDEF else not v
    if op == "defined":
        return _eval(node[1], ctx, rule, env) is not UNDEF
    if op == "filesize":
        return len(ctx.data)
    if op == "ext":
        return ctx.externals.get(node[1], node[2])
    if op == "var":
        return env.get(node[1], UNDEF)
    if op == "rule":
        return ctx.results.get((rule.namespace, node[1]), False)
    if op in ("str", "str_at", "str_in", "count", "count_in", "offset", "length"):
        name = env.get("$", node[1]) if node[1] == "$" else node[1]
        hits = ctx.matches(rule, name)
        if op == "str":
            return bool(hits)
        if op == "count":
            return len(hits)
        if op == "str_at":
            off = _eval(node[2], ctx, rule, env)
            return off is not UNDEF and any(h[0] == off for h in hits)
        if op in ("str_in", "count_in"):
            lo, hi = (_eval(x, ctx, rule, env) for x in node[2])
            if lo is UNDEF or hi is UNDEF:
                return UNDEF
            n = sum(1 for h in hits if lo <= h[0] <= hi)
            return n if op == "count_in" else n > 0
        idx = _eval(node[2], ctx, rule, env)
        if idx is UNDEF or not 1 <= idx <= len(hits):
            return UNDEF
        return hits[idx - 1][0] if op == "offset" else hits[idx - 1][1]
    if op == "of":
        _, quant, names, where = node
        if where and where[0] == "in":
            lo, hi = (_eval(x, ctx, rule, env) for x in where[1])
            test = lambda n: any(lo <= h[0] <= hi for h in ctx.matches(rule, n))
        elif where:
            at = _eval(where[1], ctx, rule, env)
            test = lambda n: any(h[0] == at for h in ctx.matches(rule, n))
        else:
            test = lambda n: bool(ctx.matches(rule, n))
        return _quantify(quant, names, test, ctx, rule, env)
    if op == "forof":
        _, quant, names, body = node
        return _quantify(quant, names, lambda n: bool(_eval(body, ctx, rule, {**env, "$": n})), ctx, rule, env)
    if op == "forin":
        _, quant, ids, it, body = node
        items = _iterate(it, ctx, rule, env)
        if items is UNDEF:
            return False
        def test(item):
            vals = item if len(ids) > 1 and isinstance(item, tuple) else (item,)
            return bool(_eval(body, ctx, rule, {**env, **dict(zip(ids, vals))}))
        return _quantify(quant, items, test, ctx, rule, env)
    if op == "int":
        _, unsigned, bits, be, off_node = node
        off = _eval(off_node, ctx, rule, env)
        n = bits // 8
        if off is UNDEF or not isinstance(off, int) or off < 0 or off + n > len(ctx.data):
            return UNDEF
        return int.from_bytes(ctx.data[off:off + n], "big" if be else "little", signed=not unsigned)
    if op == "neg":
        v = _num(_eval(node[1], ctx, rule, env))
        return UNDEF if v is UNDEF else -v
    if op == "inv":
        v = _num(_eval(node[1], ctx, rule, env))
        return UNDEF if v is UNDEF else ~int(v)
    if op == "bin":
        a, b = _num(_eval(node[2], ctx, rule, env)), _num(_eval(node[3], ctx, rule, env))
        if a is UNDEF or b is UNDEF:
            return UNDEF
        o = node[1]
        try:
            if o == "+": return a + b
            if o == "-": return a - b
            if o == "*": return a * b
            if o == "\\": return UNDEF if b == 0 else (int(a / b) if isinstance(a, int) and isinstance(b, int) else a / b)
            if o == "%": return UNDEF if b == 0 else int(math.fmod(a, b))
            a, b = int(a), int(b)
            if o == "&": return a & b
            if o == "|": return a | b
            if o == "^": return a ^ b
            if o == "<<": return a << b if 0 <= b < 64 else 0
            if o == ">>": return a >> b if 0 <= b < 64 else 0
        except (OverflowError, ValueError):
            return UNDEF
    if op == "rel":
        o, a = node[1], _eval(node[2], ctx, rule, env)
        b = node[3] if isinstance(node[3], re.Pattern) else _eval(node[3], ctx, rule, env)
        if a is UNDEF or b is UNDEF:
            return UNDEF
        if o == "matches":
            subj = a.encode("latin-1") if isinstance(a, str) else a
            return isinstance(subj, bytes) and isinstance(b, re.Pattern) and b.search(subj) is not None
        if isinstance(a, str) or isinstance(b, str):
            if not (isinstance(a, str) and isinstance(b, str)):
                return False
            al, bl = (a.lower(), b.lower()) if o.startswith("i") else (a, b)
            return {"==": a == b, "!=": a != b, "contains": b in a, "icontains": bl in al, "startswith": a.startswith(b),
                    "istartswith": al.startswith(bl), "endswith": a.endswith(b), "iendswith": al.endswith(bl),
                    "iequals": al == bl}.get(o, False)
        a, b = _num(a), _num(b)
        if a is UNDEF or b is UNDEF:
            return UNDEF
        return {"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}.get(o, False)
    if op in ("attr", "index") and _root(node)[0] != "module":
        base = _eval(node[1], ctx, rule, env)          # a loop variable holding a structure, e.g. a section
        if op == "attr":
            return base.get(node[2], UNDEF) if isinstance(base, dict) else UNDEF
        i = _eval(node[2], ctx, rule, env)
        return base[i] if isinstance(base, list) and isinstance(i, int) and 0 <= i < len(base) else UNDEF
    if op in ("module", "attr", "index", "call"):
        return _module(node, ctx, rule, env)
    raise YaraError(f"cannot evaluate {op}")


def _root(node):
    while node[0] in ("attr", "index", "call"):
        node = node[1]
    return node


def _quantify(quant, items, test, ctx, rule, env):
    items = list(items)
    kind, val = quant
    hits = 0
    if kind == "kw" and val == "any":
        return any(test(i) for i in items)
    if kind == "kw" and val == "all":
        return all(test(i) for i in items)
    if kind == "kw" and val == "none":
        return not any(test(i) for i in items)
    need = _eval(val, ctx, rule, env)
    if need is UNDEF:
        return False
    if kind == "pct":
        need = math.ceil(len(items) * need / 100)
    for i in items:
        hits += bool(test(i))
        if hits >= need:
            return True
    return hits >= need


def _iterate(it, ctx, rule, env):
    if it[0] == "range":
        lo, hi = _eval(it[1], ctx, rule, env), _eval(it[2], ctx, rule, env)
        if lo is UNDEF or hi is UNDEF:
            return UNDEF
        return range(int(lo), int(hi) + 1)
    if it[0] == "enum":
        return [_eval(x, ctx, rule, env) for x in it[1]]
    v = _eval(it[1], ctx, rule, env)
    return v if isinstance(v, list) else UNDEF


# ── modules ───────────────────────────────────────────────────────────────────

_WS2_32 = {1: "accept", 2: "bind", 3: "closesocket", 4: "connect", 5: "getpeername", 6: "getsockname", 7: "getsockopt",
           8: "htonl", 9: "htons", 10: "ioctlsocket", 11: "inet_addr", 12: "inet_ntoa", 13: "listen", 14: "ntohl",
           15: "ntohs", 16: "recv", 17: "recvfrom", 18: "select", 19: "send", 20: "sendto", 21: "setsockopt",
           22: "shutdown", 23: "socket", 51: "gethostbyaddr", 52: "gethostbyname", 53: "getprotobyname",
           54: "getprotobynumber", 55: "getservbyname", 56: "getservbyport", 57: "gethostname", 101: "WSAAsyncSelect",
           108: "WSACancelAsyncRequest", 111: "WSAGetLastError", 112: "WSASetLastError", 115: "WSAStartup",
           116: "WSACleanup", 151: "__WSAFDIsSet", 500: "WEP"}
_ORDINALS = {"ws2_32.dll": _WS2_32, "wsock32.dll": _WS2_32}


class _PE:
    """The facts the pe module exposes, read with kira-scan's own PE parser."""

    def __init__(self, data: bytes):
        self.info = info = parse_pe(data)
        self._imphash = None
        self.ok = info is not None
        if not self.ok:
            return
        e = struct.unpack_from("<I", data, 0x3C)[0]
        self.machine, _, _, _, _, self.opt_size, self.characteristics = struct.unpack_from("<HHIIIHH", data, e + 4)
        opt = e + 24
        self.magic = struct.unpack_from("<H", data, opt)[0] if opt + 2 <= len(data) else 0
        self.entry_rva = struct.unpack_from("<I", data, opt + 16)[0] if opt + 20 <= len(data) else 0
        self.subsystem = struct.unpack_from("<H", data, opt + 68)[0] if opt + 70 <= len(data) else 0
        self.linker = (data[opt + 2], data[opt + 3]) if opt + 4 <= len(data) else (0, 0)
        end = max((s.raw_pointer + s.raw_size for s in info.sections if s.raw_size), default=0)
        self.overlay = (end, len(data) - end) if 0 < end < len(data) else (0, 0)

    def rva_to_offset(self, rva):
        for s in self.info.sections:
            if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
                return s.raw_pointer + rva - s.virtual_address
        return UNDEF

    def pairs(self):
        return getattr(self.info, "import_pairs", [])

    def imphash(self):
        if self._imphash is None:
            self._imphash = self._compute_imphash()
        return self._imphash

    def _compute_imphash(self):
        parts = []
        for dll, fn in self.pairs():
            lib = dll.lower()
            base = lib.rsplit(".", 1)[0] if lib.rsplit(".", 1)[-1] in ("dll", "ocx", "sys") else lib
            if isinstance(fn, int):
                fn = _ORDINALS.get(lib, {}).get(fn, f"ord{fn}")
            parts.append(f"{base}.{fn.lower()}")
        return hashlib.md5(",".join(parts).encode()).hexdigest()


def _rx_or_eq(pat, value: str) -> bool:
    if isinstance(pat, re.Pattern):
        return pat.search(value.encode("latin-1", "replace")) is not None
    return isinstance(pat, str) and pat.lower() == value.lower()


def _module(node, ctx, rule, env):
    path, args_at = [], {}
    n = node
    while n[0] in ("attr", "index", "call"):
        if n[0] == "attr":
            path.append(n[2])
        elif n[0] == "index":
            path.append(("[]", n[2]))
        else:
            path.append(("()", n[2]))
        n = n[1]
    mod = n[1]
    path.reverse()
    if mod == "math" or mod == "hash":
        name, call = path[0], path[1] if len(path) > 1 else None
        args = [_eval(a, ctx, rule, env) for a in call[1]] if call else []
        return _math_hash(mod, name, args, ctx)
    pe = ctx.pe
    name = path[0]
    const = {"MACHINE_I386": 0x14C, "IMAGE_FILE_MACHINE_I386": 0x14C, "MACHINE_AMD64": 0x8664, "IMAGE_FILE_MACHINE_AMD64": 0x8664,
             "MACHINE_ARM64": 0xAA64, "MACHINE_ARM": 0x1C0, "MACHINE_ARMNT": 0x1C4, "DLL": 0x2000, "EXECUTABLE_IMAGE": 0x2,
             "SYSTEM": 0x1000, "RELOCS_STRIPPED": 0x1, "LARGE_ADDRESS_AWARE": 0x20, "SUBSYSTEM_NATIVE": 1,
             "SUBSYSTEM_WINDOWS_GUI": 2, "SUBSYSTEM_WINDOWS_CUI": 3, "SECTION_MEM_EXECUTE": 0x20000000,
             "SECTION_MEM_READ": 0x40000000, "SECTION_MEM_WRITE": 0x80000000, "SECTION_CNT_CODE": 0x20,
             "SECTION_CNT_INITIALIZED_DATA": 0x40}
    if name in const:
        return const[name]
    if name == "is_pe":
        return pe.ok
    if not pe.ok:
        return UNDEF
    info = pe.info
    call = path[1] if len(path) > 1 and isinstance(path[1], tuple) and path[1][0] == "()" else None
    args = [_eval(a, ctx, rule, env) for a in call[1]] if call else []
    simple = {
        "is_dll": lambda: bool(pe.characteristics & 0x2000), "is_32bit": lambda: pe.magic == 0x10B,
        "is_64bit": lambda: pe.magic == 0x20B, "number_of_sections": lambda: len(info.sections),
        "number_of_exports": lambda: len(info.exports), "number_of_imports": lambda: len(info.imported_dlls),
        "timestamp": lambda: info.timestamp, "machine": lambda: pe.machine, "characteristics": lambda: pe.characteristics,
        "subsystem": lambda: pe.subsystem, "entry_point": lambda: pe.rva_to_offset(pe.entry_rva),
        "opthdr_magic": lambda: pe.magic, "imphash": lambda: pe.imphash(),
    }
    if name in simple:
        return simple[name]()
    if name == "linker_version":
        return {"major": pe.linker[0], "minor": pe.linker[1]}.get(path[1], UNDEF) if len(path) > 1 else UNDEF
    if name == "overlay":
        return {"offset": pe.overlay[0], "size": pe.overlay[1]}.get(path[1], UNDEF) if len(path) > 1 else UNDEF
    if name == "imports":
        pairs = pe.pairs()
        if len(args) == 1:
            return sum(1 for d, _ in pairs if _rx_or_eq(args[0], d))
        if len(args) == 2:
            dll, fn = args
            if isinstance(fn, int):
                return any(_rx_or_eq(dll, d) and f == fn for d, f in pairs)
            n = sum(1 for d, f in pairs if isinstance(f, str) and _rx_or_eq(dll, d) and _rx_or_eq(fn, f))
            return n if isinstance(dll, re.Pattern) else n > 0
        return UNDEF
    if name == "exports":
        if len(args) != 1:
            return UNDEF
        return any(_rx_or_eq(args[0], e) if not isinstance(args[0], str) else e.lower() == args[0].lower() for e in info.exports)
    if name == "section_index":
        return next((i for i, s in enumerate(info.sections) if s.name == args[0]), UNDEF) if args else UNDEF
    if name == "sections":
        table = [{"name": s.name, "virtual_address": s.virtual_address, "virtual_size": s.virtual_size,
                  "raw_data_offset": s.raw_pointer, "raw_data_size": s.raw_size, "characteristics": s.characteristics}
                 for s in info.sections]
        if len(path) == 1:
            return table
        if path[1][0] != "[]":
            return UNDEF
        i = _eval(path[1][1], ctx, rule, env)
        if i is UNDEF or not 0 <= i < len(table) or len(path) < 3:
            return UNDEF
        return table[i].get(path[2], UNDEF)
    return UNDEF


def _math_hash(mod, name, args, ctx):
    if any(a is UNDEF for a in args):
        return UNDEF

    def region():
        if len(args) >= 1 and isinstance(args[0], str):
            return args[0].encode("latin-1")
        if len(args) >= 2 and isinstance(args[0], int) and isinstance(args[1], int):
            if args[0] < 0 or args[0] > len(ctx.data):
                return None
            return ctx.data[args[0]:args[0] + max(args[1], 0)]
        return None

    if mod == "hash":
        b = region()
        if b is None:
            return UNDEF
        if name == "crc32":
            return zlib.crc32(b) & 0xFFFFFFFF
        if name == "checksum32":
            return sum(b) & 0xFFFFFFFF
        return hashlib.new(name, b).hexdigest()
    if name in ("abs", "min", "max", "to_number", "in_range"):
        if name == "abs":
            return abs(args[0])
        if name == "to_number":
            return int(bool(args[0]))
        if name == "in_range":
            return args[1] <= args[0] <= args[2]
        return (min if name == "min" else max)(args[0], args[1])
    if name in ("count", "percentage"):
        byte, rest = args[0], args[1:]
        b = ctx.data if not rest else ctx.data[rest[0]:rest[0] + rest[1]]
        if not b:
            return UNDEF
        c = b.count(bytes([byte & 0xFF]))
        return c if name == "count" else c / len(b)
    b = region()
    if not b:
        return UNDEF
    if name == "entropy":
        counts = [0] * 256
        for x in b:
            counts[x] += 1
        n = len(b)
        return -sum(c / n * math.log2(c / n) for c in counts if c)
    if name == "mean":
        return sum(b) / len(b)
    if name == "deviation":
        mean = args[-1]
        return sum(abs(x - mean) for x in b) / len(b)
    return UNDEF


def target(data: bytes) -> _Ctx:
    """`data` prepared once for scanning with several rule sets: its index and string matches are shared."""
    return _Ctx(data)


def scan(rs: RuleSet, data, externals: dict | None = None) -> list[Match]:
    """Every rule of `rs` that matches `data` (bytes or a `target`), in rule order; private rules are not reported.

    `externals` gives this file's values for external variables (filename, filepath, ...); rules compiled with
    defaults for them use those defaults otherwise."""
    ctx = data if isinstance(data, _Ctx) else _Ctx(data)
    ctx.externals = externals or {}
    data = ctx.data
    out = []
    failed_globals = set()
    for rule in rs.rules:
        try:
            ok = bool(_eval(rule.condition, ctx, rule, {}))
        except (RecursionError, MemoryError):
            ok = False
        if rule.is_global and not ok:
            failed_globals.add(rule.namespace)
        ctx.results[(rule.namespace, rule.name)] = ok
    for rule in rs.rules:
        if not ctx.results.get((rule.namespace, rule.name)) or rule.private or rule.namespace in failed_globals:
            continue
        shown = [(n, h[0], data[h[0]:h[0] + min(h[1], 48)]) for n, s in rule.strings.items() if not s.private
                 for h in ctx.cache.get((id(rule), n), [])[:3]]
        out.append(Match(rule.name, rule.tags, rule.meta, shown, rule.namespace))
    return out
