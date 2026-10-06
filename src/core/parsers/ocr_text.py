# -*- coding: utf-8 -*-
"""Screenshots of scanner output: read the picture, repair what OCR breaks.

A tool's output put through OCR reaches the parsers changed in small, regular
ways, and each one cost findings (measured by rendering every console format in
tests/fixtures as a screenshot and parsing what OCR read back):

    dirb        (CODE:200|SIZE:23)          -> (CODE:200SIZE:23)       the "|" is lost
    feroxbuster 200 GET 2l 2w 23c           -> 200 GET 21 2w 23c       "l" read as "1"
    enum4linux  //10.0.0.8/public           -> 7/10.0.0.8/public
                username '', password ''    -> password II  (and "username" on the next line)
    hydra       [22][ssh] host:             -> [221[ssh] host:         "]" read as "1"
    nuclei      [http-missing-security-headers:x-frame-options] [http]
                                            -> http-missing-security headers: :x-frame-options] [http]
    gobuster    /config.php.bak (Status:    -> config.php.bak (Status:
    ffuf        .git/HEAD                   -> git/HEAD                a HIGH read as INFO
    trivy       the table's borders vanish, and "CVE-2022-37434" -> "CVE 2022-37434"
    sqlmap      "Title: ..." and "Payload: ..." run together onto one line
    Burp PoC    POST /path HTTP/1.1         -> POST/path HTTP/1.1
                HTTP/1.1 200 OK             -> HTTP/1.1 200OK          the exchange went unseen

repair_ocr_text() puts each back. It runs on OCR text only (parse_tool_file
calls it for "ocr_*" names); a report file is parsed exactly as before. Every
rule matches the broken form narrowly, so text that is already right passes
through unchanged.

findings_from_image() is the one way an uploaded image becomes findings: it reads
the picture both as laid out and strictly row by row, and keeps the reading the
parsers understood better. A terminal is read best row by row, a two-pane window
(Burp's request and response side by side) as laid out; the row reading was
only tried when the first found nothing at all, so a screenshot that gave 1 of
4 findings kept the 1.
"""
import re

_METHODS = "GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS"
_PROTOS = "http|dns|ssl|tcp|network|file|headless|code|javascript|whois|websocket"
_NUCLEI_SEV = "info|low|medium|high|critical|unknown"
_TRIVY_SEV = "UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL"
_TRIVY_STATUS = "fixed|affected|will_not_fix|fix_deferred|end_of_life|under_investigation|unknown"
# Hydra's service names and their default ports, for a "[22]" read as "[221".
_SERVICE_PORTS = {
    "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "http": 80, "http-get": 80, "http-post": 80,
    "http-get-form": 80, "http-post-form": 80, "http-head": 80, "pop3": 110, "imap": 143,
    "https": 443, "https-get": 443, "https-post": 443, "https-get-form": 443, "https-post-form": 443,
    "smb": 445, "smtps": 465, "imaps": 993, "pop3s": 995, "mssql": 1433, "mysql": 3306,
    "rdp": 3389, "postgres": 5432, "vnc": 5900, "redis": 6379, "mongodb": 27017,
}
_CIPHER_PARTS = ("RSA|ECDHE|DHE|ECDH|DH|PSK|ECDSA|DSS|ANON|WITH|AES|CAMELLIA|ARIA|SEED|IDEA|CHACHA20|POLY1305|"
                 "3DES|EDE|DES|RC4|RC2|NULL|EXPORT|EXPORT1024|CBC|GCM|CCM|CCM8|SHA|SHA256|SHA384|MD5|"
                 "128|256|40|56|8")


def _is_empty_quotes(word):
    """What OCR makes of an empty quoted name (''): "II", "1I", "ll", "||", ...
    -- two to four quote-like strokes and nothing else."""
    return bool(re.fullmatch(r"[\"'`‘’“”Il1|]{2,4}", word)) and not word.isdigit()


def _repair_line(line, known_ports):
    l = line
    # CVE ids that lost a hyphen: "CVE 2022-37434", "CVE-2022 37434". One that
    # is already right is left exactly as written (case included, in URLs).
    l = re.sub(r'\b(CVE)([\s_.-]*)(\d{4})([\s_.-]*)(\d{4,7})\b',
               lambda m: m.group(0) if (m.group(2), m.group(4)) == ("-", "-")
               else f"{m.group(1)}-{m.group(3)}-{m.group(5)}", l, flags=re.I)
    # An HTTP exchange with its spaces squeezed out.
    l = re.sub(rf'^(\s*)({_METHODS})(?=/)', r'\1\2 ', l)
    l = re.sub(r'\bHTTP/(\d(?:\.\d)?)\s*(\d{3})(?=[A-Za-z])', r'HTTP/\1 \2 ', l)
    l = re.sub(r'^(\s*Host)\s+(?=[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?::\d+)?\s*$)', r'\1: ', l, flags=re.I)
    # dirb: "(CODE:200SIZE:23)", "(CODE:2001SIZE:23)", "(CODE: - 2001SIZE:23)".
    l = re.sub(r'\(CODE:[\s\-:.]*(\d{3})\s*[|lI1!]?\s*SIZE:\s*(\d+)\)', r'(CODE:\1|SIZE:\2)', l)
    # A TLS cipher-suite name with its underscores read as spaces
    # ("TLS_ RSA WITH AES_128 CBC_SHA"). Joined only through the vocabulary of
    # cipher-suite parts, so ordinary words after it are left alone.
    l = re.sub(rf'\b(?:TLS|SSL)(?:[_ ]+(?:{_CIPHER_PARTS}))+\b',
               lambda m: re.sub(r'[_ ]+', '_', m.group(0)), l)
    # A dash between words read as "i", "l" or "|" ("blind i WHERE or HAVING").
    # Only before a capital: a lone lower-case "i" is not English there.
    l = re.sub(r'(?<=\S) [il|] (?=[A-Z])', ' - ', l)
    # Percent-encoding in a path: "%" read as "8" ("/.%2e/" -> "/.82e/").
    l = re.sub(r'(?<=[./])8(2[eEfF]|5[cC])(?=[./])', r'%\1', l)
    # feroxbuster: "200 GET 21 2w 23c http://..." (the "l" of 2l read as 1).
    m = re.match(rf'^(\s*\d{{3}}\s+(?:{_METHODS}))\s+(\d+)[lI|]?\s+(\d+)[wW]?\s+(\d+)[cC]?\s+(https?://\S.*)$', l)
    if m:
        l = f"{m.group(1)} {m.group(2)}l {m.group(3)}w {m.group(4)}c {m.group(5)}"
    # A URL's "://" split or short of a slash ("http: //", "https : //", "http: /shop"),
    # and gobuster's "Url" read "Ur1".
    l = re.sub(r'\b(https?)\s*:\s*/\s*/?\s*(?=[A-Za-z0-9\[])', r'\1://', l)
    l = re.sub(r'\bUr[1lI|](?=/Domain\b|\s*:)', 'Url', l)
    # enum4linux: "7/10.0.0.8/public  Mapping: OK" -- the "//" of a share path.
    l = re.sub(r'^(\s*)(?:[71lI|]/|/[71lI|]|/)(?=[\w.-]+/\S+\s+Mapping:)', r'\1//', l)
    # enum4linux: a section banner with OCR debris after it
    # ("Session Check on 10.0.0.8 )== =") -- the host is read from its end.
    l = re.sub(r'^(.*\b(?:Session Check|Target Information) on \S+?\s*\)).*$', r'\1', l)
    # Hydra: "[22] [ssh] host:" (a space), "[221[ssh] host:" ("]" read as "1"),
    # "[2211ssh] host:" (both brackets read as "1"). A damaged bracket is
    # repaired only to a port the run itself names (its "attacking" line) or the
    # service's default port.
    l = re.sub(r'^(\s*\[\d+\])\s+(\[[\w-]+\]\s+host:)', r'\1\2', l, flags=re.I)
    m = re.match(r'^(\s*)\[(\d+?)[1lI|\]]{1,2}\[?([a-z][\w-]*)\](\s*host:.*)$', l, re.I)
    if m and not re.match(r'^\s*\[\d+\]\[', l):
        port = int(m.group(2))
        if port in known_ports or _SERVICE_PORTS.get(m.group(3).lower()) == port:
            l = f"{m.group(1)}[{m.group(2)}][{m.group(3)}]{m.group(4)}"
    # nuclei: "[id] [proto] [sev] url" with brackets read as "(", ")", "l" or
    # lost ("(apache-detect] [http] [infol", "http-missing-security headers: :x-frame-options]").
    m = re.match(rf'^\s*[\[({{]?\s*([^\[\](){{}}\s][^\[\](){{}}]*?)\s*[\])}}]?\s*[\[({{]\s*({_PROTOS})\s*[\])}}lI1|]\s*'
                 rf'[\[({{]\s*({_NUCLEI_SEV})\s*[\])}}lI1|]?\s*(\S.*)$', l, re.I)
    if m and not re.match(rf'^\s*\[[\w.:/-]+\]\s+\[(?:{_PROTOS})\]\s+\[(?:{_NUCLEI_SEV})\]\s', l, re.I):
        tid = re.sub(r'\s*:[\s:]*', ':', m.group(1).strip())
        tid = re.sub(r'\s+', '-', tid)
        l = f"[{tid}] [{m.group(2).lower()}] [{m.group(3).lower()}] {m.group(4)}"
    # gobuster: a path that lost its leading "/".
    l = re.sub(r'^(\s*)(?![/\[+=])([\w.~-][^\s]*)(\s+\(Status:\s*\d{3}\))', r'\1/\2\3', l)
    # Dot-files that lost their dot: ".git/HEAD" read as "git/HEAD".
    l = re.sub(r'(?<![\w.])(git/(?:HEAD|config|index)\b|svn/(?:entries|wc\.db)\b|ht(?:access|passwd)\b|DS_Store\b)',
               r'.\1', l)
    # sqlmap: two or more of its fields run together onto one line. (One field
    # alone -- WPScan's "[!] Title:" -- is left as it is.)
    fields = list(re.finditer(r'\b(?:Parameter|Type|Title|Payload|Vector):\s', l))
    if len(fields) >= 2:
        for f in reversed(fields[1:]):
            l = l[:f.start()].rstrip() + "\n    " + l[f.start():]
    return l


def _join_split_hydra(lines):
    """Hydra's "host: H   login: U   password: P", split over three lines."""
    out, i = [], 0
    while i < len(lines):
        l = lines[i]
        if (re.match(r'^\s*\[\d+\]\[[\w-]+\]\s+host:\s*\S+\s*$', l, re.I) and i + 2 < len(lines)
                and re.match(r'^\s*login:\s*\S+\s*$', lines[i + 1], re.I)
                and re.match(r'^\s*password:\s*\S*\s*$', lines[i + 2], re.I)):
            out.append(f"{l.rstrip()}   {lines[i + 1].strip()}   {lines[i + 2].strip()}")
            i += 3
            continue
        out.append(l)
        i += 1
    return out


def _repair_enum4linux_null_session(lines):
    """'[+] Server H allows sessions using username '', password ''' as OCR reads
    it: "using password II", sometimes with "username" on the next line. Only
    when nothing else is in the sentence -- a named user ('guest') is left alone."""
    out = list(lines)
    for i, l in enumerate(lines):
        m = re.search(r'Server\s+(\S+)\s+allows sessions?\s+using\b(.*)$', l, re.I)
        if not m:
            continue
        # The sentence itself; the next line only when a word of it moved there.
        window = m.group(2)
        if not (re.search(r'\busername\b', window, re.I) and re.search(r'\bpassword\b', window, re.I)):
            window += " " + (lines[i + 1] if i + 1 < len(lines) else "")
        words = [w for w in re.split(r'[\s,]+', window) if w]
        # Quote debris: quote-like strokes, or a lone letter or symbol ("a I :").
        # A name is three or more letters or digits -- 'guest' stays a name.
        named = [w for w in words if w.lower() not in ("username", "password") and not _is_empty_quotes(w)
                 and not re.fullmatch(r"[\W_]+|[A-Za-z]", w)]
        if not named and any(w.lower() == "username" for w in words) and any(w.lower() == "password" for w in words):
            out[i] = f"[+] Server {m.group(1)} allows sessions using username '', password ''"
    return out


def _repair_trivy_table(lines):
    """A Trivy table without its borders: rebuild the "│"-ruled rows (and the
    "=====" under the target name) the Trivy parser reads."""
    hdr_i = next((i for i, l in enumerate(lines)
                  if re.search(r'\bLibrary\s+Vulnerability(?:\s+ID)?\s+Severity\b', l) and "│" not in l and "|" not in l),
                 None)
    if hdr_i is None:
        return lines
    names = re.findall(r'Library|Vulnerability ID|Vulnerability|Severity|Status|Installed Version|Fixed Version|Title',
                       lines[hdr_i])
    has_status = "Status" in names
    out = list(lines[:hdr_i])
    # The target line ("shop:1.0 (debian 11.6)") lost its "=====" underline.
    for j in range(len(out) - 1, -1, -1):
        if out[j].strip() and not out[j].strip().startswith("Total:"):
            if j + 1 < len(out) and set(out[j + 1].strip()) == {"="}:
                break
            out.insert(j + 1, "=" * max(len(out[j].strip()), 5))
            break
    out.append("│ " + " │ ".join(names) + " │")
    row_re = re.compile(rf'^\s*(?:(\S+)\s+)?((?:CVE|GHSA|DLA|DSA|RHSA|ALAS|OSV)[-\w.]*\d)\s+({_TRIVY_SEV})\s+(.*)$')
    for l in lines[hdr_i + 1:]:
        m = row_re.match(l)
        if m:
            # The table's vertical rules survive as stray "I" / "|" / "l" tokens
            # among the status and version cells (a title keeps its words).
            lib, vid, sev = m.group(1) or "", m.group(2), m.group(3)
            toks = m.group(4).split()
            rest = [t for t in toks[:5] if t not in ("I", "|", "l", "¦", "1")] + toks[5:]
            status = ""
            if has_status and rest and re.fullmatch(_TRIVY_STATUS, rest[0], re.I):
                status = rest.pop(0)
            inst = rest.pop(0) if rest else ""
            fixed = rest.pop(0) if rest and re.search(r'\d', rest[0]) and not rest[0].endswith(":") else ""
            title = " ".join(rest)
            cells = {"Library": lib, "Vulnerability": vid, "Vulnerability ID": vid, "Severity": sev,
                     "Status": status, "Installed Version": inst, "Fixed Version": fixed, "Title": title}
            out.append("│ " + " │ ".join(cells.get(n, "") for n in names) + " │")
        elif l.strip() and not l.strip().startswith("Total:"):
            out.append("│ " + " │ ".join([""] * (len(names) - 1) + [l.strip()]) + " │")
        else:
            out.append(l)
    return out


def repair_ocr_text(text):
    """OCR text of a screenshot, with the damage described above repaired."""
    if not text:
        return text
    known_ports = {int(p) for p in re.findall(r'attacking\s+[\w-]+://[^\s:/]+:(\d+)', text, re.I)}
    lines = [_repair_line(l, known_ports) for l in text.split("\n")]
    lines = "\n".join(lines).split("\n")          # sqlmap repairs can add line breaks
    lines = _join_split_hydra(lines)
    lines = _repair_enum4linux_null_session(lines)
    lines = _repair_trivy_table(lines)
    return "\n".join(lines)


# ── an uploaded image -> findings ────────────────────────────────────────────

_PLACEHOLDER_TARGETS = {"", "targethost", "target host", "not recorded", "web application endpoint",
                        "target scope evaluated", "scoped host targets"}


def reading_score(findings):
    """How well the parsers understood one reading: vulnerabilities first, then
    findings that name a real target, then findings at all."""
    actionable = sum(1 for f in findings if str(getattr(f, "severity", "") or "").upper() not in ("INFO", "INFORMATIONAL"))
    targeted = sum(1 for f in findings
                   if str(getattr(f, "target", "") or "").strip().lower() not in _PLACEHOLDER_TARGETS)
    return (actionable, targeted, len(findings))


def findings_from_image(image_bytes, fname, framework="", first_text=None):
    """(findings, the OCR text they came from) for an uploaded image.

    `first_text`: OCR text the upload already extracted, if any. Both the
    laid-out and the row-by-row reading are parsed; the better one is kept (a
    tie keeps the laid-out reading, as before)."""
    import io
    from src.core.parsers import parse_tool_file
    from src.core.parsers.doc_parsers import extract_text, ocr_image_row_text

    def _parse(text):
        a, i = parse_tool_file("ocr_" + fname + ".txt", text, framework=framework)
        return (a if isinstance(a, list) else []) + (i if isinstance(i, list) else [])

    raw = (first_text or "").strip()
    if not raw and image_bytes:
        try:
            buf = io.BytesIO(image_bytes)
            buf.name = fname
            raw = extract_text(buf) or ""
        except Exception:
            raw = ""
    best, best_text = ([], raw)
    if raw and len(raw.strip()) > 10:
        best = _parse(raw)
    if image_bytes:
        try:
            rows = ocr_image_row_text(image_bytes)
        except Exception as err:
            print(f"[VAPT] Row-wise OCR re-read of '{fname}' skipped: {err}", flush=True)
            rows = ""
        if rows and len(rows.strip()) > 10 and rows.strip() != raw.strip():
            row_findings = _parse(rows)
            if reading_score(row_findings) > reading_score(best):
                best, best_text = row_findings, rows
    return best, (best_text or raw)
