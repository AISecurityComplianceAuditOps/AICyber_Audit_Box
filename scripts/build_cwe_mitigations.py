# -*- coding: utf-8 -*-
"""Build src/core/knowledge/cwe_mitigations.json from MITRE's CWE list.

Run on a machine with internet, before a release -- never on the appliance:

    python scripts/build_cwe_mitigations.py                 # downloads cwec_latest.xml.zip
    python scripts/build_cwe_mitigations.py path/to/cwec_v4.20.xml[.zip]

What it keeps, per weakness: its name and MITRE's "Potential Mitigations"
(phase + text), exactly as MITRE writes them, flattened from XHTML to plain
text. The VAPT pipeline uses them only for a finding whose own report or scan
gave no remediation (src/core/parsers/control_mapper.py), labelled as MITRE's
general guidance.

OWASP Cheat Sheet Series links are added for the common web weaknesses. Only
the title and URL are stored -- OWASP's text is CC BY-SA and is not copied --
and each URL is fetched here, so a link that does not resolve is left out.

CWE Terms of Use: free for commercial use provided MITRE's copyright
designation and the licence are reproduced in any copy. Both are written into
the output file's "notice".
"""
import io
import json
import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "src", "core", "knowledge", "cwe_mitigations.json")
NS = {"c": "http://cwe.mitre.org/cwe-7"}

NOTICE = (
    "Contains content from the Common Weakness Enumeration (CWE), Copyright (c) 2006-2026, "
    "The MITRE Corporation. CWE and the CWE logo are trademarks of The MITRE Corporation. "
    "CWE is free to use by any organization or individual for any research, development, and/or "
    "commercial purposes, per these CWE Terms of Use. Accordingly, The MITRE Corporation hereby "
    "grants you a non-exclusive, royalty-free license to use CWE for research, development, and "
    "commercial purposes. Any copy you make for such purposes is authorized on the condition that "
    "you reproduce MITRE's copyright designation and this license in any such copy. "
    "https://cwe.mitre.org/about/termsofuse.html"
)

# OWASP Cheat Sheet Series pages, by the CWE they address. Title and URL only.
_CS = "https://cheatsheetseries.owasp.org/cheatsheets/%s.html"
OWASP_CHEAT_SHEETS = {
    "CWE-89": "SQL_Injection_Prevention_Cheat_Sheet",
    "CWE-79": "Cross_Site_Scripting_Prevention_Cheat_Sheet",
    "CWE-352": "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet",
    "CWE-918": "Server_Side_Request_Forgery_Prevention_Cheat_Sheet",
    "CWE-611": "XML_External_Entity_Prevention_Cheat_Sheet",
    "CWE-601": "Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
    "CWE-1021": "Clickjacking_Defense_Cheat_Sheet",
    "CWE-78": "OS_Command_Injection_Defense_Cheat_Sheet",
    "CWE-434": "File_Upload_Cheat_Sheet",
    "CWE-639": "Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet",
    "CWE-269": "Authorization_Cheat_Sheet",
    "CWE-285": "Authorization_Cheat_Sheet",
    "CWE-287": "Authentication_Cheat_Sheet",
    "CWE-307": "Authentication_Cheat_Sheet",
    "CWE-319": "Transport_Layer_Security_Cheat_Sheet",
    "CWE-311": "Transport_Layer_Security_Cheat_Sheet",
    "CWE-326": "Transport_Layer_Security_Cheat_Sheet",
    "CWE-327": "Transport_Layer_Security_Cheat_Sheet",
    "CWE-523": "HTTP_Strict_Transport_Security_Cheat_Sheet",
    "CWE-614": "Session_Management_Cheat_Sheet",
    "CWE-1004": "Session_Management_Cheat_Sheet",
    "CWE-384": "Session_Management_Cheat_Sheet",
    "CWE-613": "Session_Management_Cheat_Sheet",
    "CWE-209": "Error_Handling_Cheat_Sheet",
    "CWE-502": "Deserialization_Cheat_Sheet",
    "CWE-1104": "Vulnerable_Dependency_Management_Cheat_Sheet",
    "CWE-1395": "Vulnerable_Dependency_Management_Cheat_Sheet",
    "CWE-770": "Denial_of_Service_Cheat_Sheet",
    "CWE-1321": "Prototype_Pollution_Prevention_Cheat_Sheet",
}


def _text(el):
    """An XHTML-bearing element as plain text: paragraphs and list items kept
    apart with a space, everything else run together."""
    if el is None:
        return ""
    parts = []
    for t in el.itertext():
        parts.append(t)
    return " ".join(" ".join(parts).split())


def _load(path):
    if path is None:
        print("downloading", URL)
        data = urllib.request.urlopen(URL, timeout=120).read()
        path = io.BytesIO(data)
    if hasattr(path, "read") or str(path).lower().endswith(".zip"):
        z = zipfile.ZipFile(path)
        name = z.namelist()[0]
        return name, z.read(name)
    return os.path.basename(path), open(path, "rb").read()


def _url_ok(url):
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "cwe-kb-builder"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status == 200
    except Exception:
        return False


def main():
    name, raw = _load(sys.argv[1] if len(sys.argv) > 1 else None)
    root = ET.fromstring(raw)
    version, date = root.get("Version"), root.get("Date")
    cwes = {}
    for w in root.findall("c:Weaknesses/c:Weakness", NS):
        if (w.get("Status") or "").lower() == "deprecated":
            continue
        mitigations = []
        for m in w.findall("c:Potential_Mitigations/c:Mitigation", NS):
            text = _text(m.find("c:Description", NS))
            if not text:
                continue
            phases = [p.text.strip() for p in m.findall("c:Phase", NS) if p.text]
            mitigations.append({"phase": phases, "text": text})
        if mitigations:
            cwes["CWE-" + w.get("ID")] = {"name": w.get("Name"), "abstraction": w.get("Abstraction"),
                                          "mitigations": mitigations}

    verified = {}
    for cwe, slug in OWASP_CHEAT_SHEETS.items():
        url = _CS % slug
        if slug not in verified:
            verified[slug] = _url_ok(url)
            print(("ok   " if verified[slug] else "DROP ") + url)
        if verified[slug] and cwe in cwes:
            cwes[cwe]["owasp_cheat_sheet"] = {"title": "OWASP " + slug.replace("_", " "), "url": url}

    out = {"source": "MITRE Common Weakness Enumeration (CWE)", "file": name, "version": version,
           "date": date, "notice": NOTICE, "cwe": cwes}
    with io.open(OUT, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=0, sort_keys=True)
    print("CWE %s (%s): %d weaknesses with mitigations -> %s (%d KB)"
          % (version, date, len(cwes), OUT, os.path.getsize(OUT) // 1024))


if __name__ == "__main__":
    main()
