# -*- coding: utf-8 -*-
"""Build src/core/knowledge/cisa_kev.json from CISA's Known Exploited
Vulnerabilities (KEV) catalog.

Run on a machine with internet, before a release -- never on the appliance:

    python scripts/build_cisa_kev.py                       # downloads the catalog
    python scripts/build_cisa_kev.py path/to/known_exploited_vulnerabilities.json

The VAPT pipeline marks a finding whose CVE is in the catalog as known to be
exploited in the wild, and -- only where the scan or report gave no
remediation -- uses CISA's required action (src/core/parsers/control_mapper.py).
It never changes a finding's severity.

Licence: the KEV database is distributed under CC0 1.0 (cisagov/kev-data). It
may be used in any legal manner; it does not authorise use of the CISA logo or
DHS seal, nor imply endorsement by CISA or DHS.
"""
import io
import json
import os
import sys
import urllib.request

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "src", "core", "knowledge", "cisa_kev.json")
NOTICE = ("CISA Known Exploited Vulnerabilities catalog, distributed under CC0 1.0 "
          "(https://github.com/cisagov/kev-data). Use does not imply endorsement by CISA or DHS.")


def main():
    if len(sys.argv) > 1:
        data = json.load(io.open(sys.argv[1], encoding="utf-8"))
    else:
        print("downloading", URL)
        data = json.loads(urllib.request.urlopen(URL, timeout=120).read().decode("utf-8"))
    cves = {}
    for v in data.get("vulnerabilities", []):
        cve = str(v.get("cveID") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        cves[cve] = {
            "vendor": " ".join(str(v.get("vendorProject") or "").split()),
            "product": " ".join(str(v.get("product") or "").split()),
            "name": " ".join(str(v.get("vulnerabilityName") or "").split()),
            "date_added": v.get("dateAdded") or "",
            "required_action": " ".join(str(v.get("requiredAction") or "").split()),
            "ransomware_use": v.get("knownRansomwareCampaignUse") or "Unknown",
            "cwes": [str(c).upper() for c in (v.get("cwes") or [])],
        }
    out = {"source": data.get("title") or "CISA Known Exploited Vulnerabilities Catalog",
           "version": data.get("catalogVersion"), "date": data.get("dateReleased"),
           "notice": NOTICE, "cves": cves}
    with io.open(OUT, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=0, sort_keys=True)
    print("KEV %s: %d CVEs -> %s (%d KB)" % (out["version"], len(cves), OUT, os.path.getsize(OUT) // 1024))


if __name__ == "__main__":
    main()
