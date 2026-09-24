# -*- coding: utf-8 -*-
"""Every other output format the tools produce, each with the answer written first.

(filename, content, expect) -- expect keys:
  min      : at least this many findings (actionable + informational)
  max      : at most this many
  mention  : each string must appear in some finding's title/description/evidence
  sev      : {substring of title: severity}
  target   : substring every finding's target must contain
  none     : strings no finding title may contain (junk)
"""

S = {}

# ── Nikto ────────────────────────────────────────────────────────────────────
S["nikto_csv"] = ("nikto.csv", '''"Nikto - v2.1.6/2.1.5"
"shop.test","10.0.0.5","80","","","",""
"shop.test","10.0.0.5","80","","GET","/","The anti-clickjacking X-Frame-Options header is not present."
"shop.test","10.0.0.5","80","","GET","/","The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type"
"shop.test","10.0.0.5","80","","HEAD","","Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch."
"shop.test","10.0.0.5","80","OSVDB-3233","GET","/icons/README","/icons/README: Apache default file found."
"shop.test","10.0.0.5","80","OSVDB-3092","GET","/phpmyadmin/","/phpmyadmin/: phpMyAdmin directory found"
''', dict(min=5, max=5, mention=["X-Frame-Options", "X-Content-Type-Options", "outdated", "default file", "phpMyAdmin"],
          sev={"outdated": "MEDIUM"}, target="shop.test"))

S["nikto_xml"] = ("nikto.xml", '''<?xml version="1.0" ?>
<!DOCTYPE niktoscan SYSTEM "/var/lib/nikto/docs/nikto.dtd">
<niktoscan hoststest="0" options="-h shop.test -Format xml -o nikto.xml" version="2.1.6" scanstart="Tue Jun 24 10:00:00 2025" scanend="Tue Jun 24 10:05:00 2025" scanelapsed=" seconds" nxmlversion="1.2">
<scandetails targetip="10.0.0.5" targethostname="shop.test" targetport="80" targetbanner="Apache/2.4.29 (Ubuntu)" starttime="2025-06-24 10:00:00" sitename="http://shop.test:80/" siteip="http://10.0.0.5:80/" hostheader="shop.test" errors="0" checks="8102">
<item id="999986" osvdbid="0" osvdblink="" method="GET">
<description><![CDATA[The anti-clickjacking X-Frame-Options header is not present.]]></description>
<uri><![CDATA[/]]></uri>
<namelink><![CDATA[http://shop.test:80/]]></namelink>
<iplink><![CDATA[http://10.0.0.5:80/]]></iplink>
</item>
<item id="600050" osvdbid="0" osvdblink="" method="HEAD">
<description><![CDATA[Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.]]></description>
<uri><![CDATA[]]></uri>
<namelink><![CDATA[http://shop.test:80/]]></namelink>
<iplink><![CDATA[http://10.0.0.5:80/]]></iplink>
</item>
<item id="003233" osvdbid="3233" osvdblink="http://osvdb.org/3233" method="GET">
<description><![CDATA[/icons/README: Apache default file found.]]></description>
<uri><![CDATA[/icons/README]]></uri>
<namelink><![CDATA[http://shop.test:80/icons/README]]></namelink>
<iplink><![CDATA[http://10.0.0.5:80/icons/README]]></iplink>
</item>
<item id="003092" osvdbid="3092" osvdblink="http://osvdb.org/3092" method="GET">
<description><![CDATA[/phpmyadmin/: phpMyAdmin directory found]]></description>
<uri><![CDATA[/phpmyadmin/]]></uri>
<namelink><![CDATA[http://shop.test:80/phpmyadmin/]]></namelink>
<iplink><![CDATA[http://10.0.0.5:80/phpmyadmin/]]></iplink>
</item>
<statistics elapsed="300" itemsfound="4" itemstested="8102" endtime="2025-06-24 10:05:00" />
</scandetails>
</niktoscan>
''', dict(min=4, max=4, mention=["X-Frame-Options", "outdated", "default file", "phpMyAdmin"],
          sev={"outdated": "MEDIUM"}, target="shop.test"))

S["nikto_json"] = ("nikto.json", '''[{"host":"shop.test","ip":"10.0.0.5","port":"80","banner":"Apache/2.4.29 (Ubuntu)","vulnerabilities":[
{"id":"999986","references":"","method":"GET","url":"/","msg":"The anti-clickjacking X-Frame-Options header is not present."},
{"id":"600050","references":"","method":"HEAD","url":"/","msg":"Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch."},
{"id":"003233","references":"","method":"GET","url":"/icons/README","msg":"Apache default file found."},
{"id":"003092","references":"","method":"GET","url":"/phpmyadmin/","msg":"phpMyAdmin directory found."}
]}]
''', dict(min=4, max=4, mention=["X-Frame-Options", "outdated", "default file", "phpMyAdmin"],
          sev={"outdated": "MEDIUM"}, target="shop.test"))

# ── sqlmap ───────────────────────────────────────────────────────────────────
S["sqlmap_log"] = ("log", '''sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 5102=5102

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=1 UNION ALL SELECT NULL,CONCAT(0x7176627071,0x4a6b),NULL-- -
---
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.29, PHP 7.2.24
back-end DBMS: MySQL >= 5.0.12
''', dict(min=1, mention=["id"], sev={"SQL": "CRITICAL"}))

S["sqlmap_results_csv"] = ("results-06242025_1000am.csv", '''Target URL,Place,Parameter,Technique(s),Note(s)
http://shop.test/product.php?id=1,GET,id,BTU,
http://shop.test/search.php,POST,q,T,
''', dict(min=2, mention=["id", "q"], sev={"'id'": "CRITICAL"}, target="shop.test"))

S["sqlmap_clean"] = ("sqlmap_clean.txt", '''        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.7.2#stable}
|_ -| . [)]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[*] starting @ 10:00:00 /2025-06-24/

[10:00:01] [INFO] testing connection to the target URL
[10:00:02] [INFO] testing if GET parameter 'id' is dynamic
[10:00:03] [WARNING] GET parameter 'id' does not appear to be dynamic
[10:00:20] [WARNING] GET parameter 'id' does not seem to be injectable
[10:00:20] [CRITICAL] all tested parameters do not appear to be injectable.

[*] ending @ 10:00:20 /2025-06-24/
''', dict(min=0, max=0))

# ── Directory brute-forcers ──────────────────────────────────────────────────
S["gobuster_outfile"] = ("gobuster_out.txt", '''/.git/HEAD            (Status: 200) [Size: 23]
/admin                (Status: 301) [Size: 312] [--> http://shop.test/admin/]
/index.php            (Status: 200) [Size: 10918]
/server-status        (Status: 403) [Size: 277]
''', dict(min=4, mention=[".git", "admin"], sev={".git": "HIGH", "/admin": "MEDIUM", "index.php": "INFO"}))

S["gobuster_v2"] = ("gobuster_v2.txt", '''
=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://shop.test/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirb/common.txt
[+] Status codes : 200,204,301,302,307,403
[+] Timeout      : 10s
=====================================================
2025/06/24 10:00:00 Starting gobuster
=====================================================
/.git/HEAD (Status: 200)
/admin (Status: 301)
/index.php (Status: 200)
/server-status (Status: 403)
=====================================================
2025/06/24 10:01:00 Finished
=====================================================
''', dict(min=4, mention=[".git", "admin"], sev={".git": "HIGH", "index.php": "INFO"}, target="shop.test"))

S["dirb"] = ("dirb.txt", '''
-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Tue Jun 24 10:00:00 2025
URL_BASE: http://shop.test/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://shop.test/ ----
+ http://shop.test/.git/HEAD (CODE:200|SIZE:23)
==> DIRECTORY: http://shop.test/admin/
+ http://shop.test/index.php (CODE:200|SIZE:10918)
+ http://shop.test/server-status (CODE:403|SIZE:277)

-----------------
END_TIME: Tue Jun 24 10:05:00 2025
DOWNLOADED: 4612 - FOUND: 3
''', dict(min=4, mention=[".git", "admin", "server-status"], sev={".git": "HIGH", "index.php": "INFO"},
          target="shop.test"))

S["ffuf_console"] = ("ffuf.txt", '''
        /'___\\  /'___\\           /'___\\
       /\\ \\__/ /\\ \\__/  __  __  /\\ \\__/
       \\ \\ ,__\\\\ \\ ,__\\/\\ \\/\\ \\ \\ \\ ,__\\
        \\ \\ \\_/ \\ \\ \\_/\\ \\ \\_\\ \\ \\ \\ \\_/
         \\ \\_\\   \\ \\_\\  \\ \\____/  \\ \\_\\
          \\/_/    \\/_/   \\/___/    \\/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://shop.test/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.git/HEAD               [Status: 200, Size: 23, Words: 2, Lines: 2, Duration: 12ms]
admin                   [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 10ms]
index.php               [Status: 200, Size: 10918, Words: 900, Lines: 200, Duration: 15ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 9ms]
:: Progress: [4614/4614] :: Job [1/1] :: 400 req/sec :: Duration: [0:00:12] :: Errors: 0 ::
''', dict(min=4, mention=[".git", "admin"], sev={".git": "HIGH", "index.php": "INFO"}, target="shop.test"))

S["ffuf_json"] = ("ffuf.json", '''{"commandline":"ffuf -u http://shop.test/FUZZ -w /usr/share/wordlists/dirb/common.txt -o ffuf.json","time":"2025-06-24T10:00:00+05:30","results":[
{"input":{"FFUFHASH":"a1","FUZZ":".git/HEAD"},"position":12,"status":200,"length":23,"words":2,"lines":2,"content-type":"text/plain","redirectlocation":"","scraper":{},"duration":12000000,"resultfile":"","url":"http://shop.test/.git/HEAD","host":"shop.test"},
{"input":{"FFUFHASH":"a2","FUZZ":"admin"},"position":80,"status":301,"length":312,"words":20,"lines":10,"content-type":"text/html","redirectlocation":"http://shop.test/admin/","scraper":{},"duration":10000000,"resultfile":"","url":"http://shop.test/admin","host":"shop.test"},
{"input":{"FFUFHASH":"a3","FUZZ":"index.php"},"position":2000,"status":200,"length":10918,"words":900,"lines":200,"content-type":"text/html","redirectlocation":"","scraper":{},"duration":15000000,"resultfile":"","url":"http://shop.test/index.php","host":"shop.test"}
],"config":{"url":"http://shop.test/FUZZ","method":"GET","outputfile":"ffuf.json","outputformat":"json"}}
''', dict(min=3, mention=[".git", "admin"], sev={".git": "HIGH", "index.php": "INFO"}, target="shop.test"))

S["feroxbuster"] = ("ferox.txt", '''
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \\ \\_/ | |  \\ |__
|    |___ |  \\ |  \\ | \\__,    \\__/ / \\ | |__/ |___
by Ben "epi" Risher                    ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://shop.test
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
───────────────────────────┴──────────────────────
200      GET        2l        2w       23c http://shop.test/.git/HEAD
301      GET        9l       28w      312c http://shop.test/admin => http://shop.test/admin/
200      GET      200l      900w    10918c http://shop.test/index.php
403      GET        9l       28w      277c http://shop.test/server-status
[####################] - 30s    30000/30000   0s      found:4       errors:0
''', dict(min=4, mention=[".git", "admin"], sev={".git": "HIGH", "index.php": "INFO"}, target="shop.test"))

# ── Credential attacks ───────────────────────────────────────────────────────
S["hydra_outfile"] = ("hydra_out.txt", '''# Hydra v9.5 run at 2025-06-24 10:00:00 on 10.0.0.5 ssh (hydra -l admin -P /usr/share/wordlists/rockyou.txt -o hydra_out.txt ssh://10.0.0.5)
[22][ssh] host: 10.0.0.5   login: admin   password: Summer2024!
''', dict(min=1, max=1, mention=["admin", "ssh"], sev={"credential": "CRITICAL"}, target="10.0.0.5",
          none=["Summer2024!"]))

S["hydra_json"] = ("hydra.json", '''{ "generator": {
\t"software": "Hydra", "version": "v9.5", "built": "2025-06-24 10:00:00",
\t"server": "10.0.0.5", "service": "ssh", "jsonoutputversion": "1.00",
\t"commandline": "hydra -b json -o hydra.json -l admin -P rockyou.txt ssh://10.0.0.5"
\t},
"results": [
\t{"port": 22, "service": "ssh", "host": "10.0.0.5", "login": "admin", "password": "Summer2024!"}
\t],
"success": true,
"errormessages": [ ],
"quantityfound": 1  }
''', dict(min=1, max=1, mention=["admin", "ssh"], sev={"credential": "CRITICAL"}, target="10.0.0.5",
          none=["Summer2024!"]))

S["medusa"] = ("medusa.txt", '''Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>

ACCOUNT CHECK: [ssh] Host: 10.0.0.5 (1 of 1, 0 complete) User: admin (1 of 1, 0 complete) Password: 123456 (1 of 3 complete)
ACCOUNT CHECK: [ssh] Host: 10.0.0.5 (1 of 1, 0 complete) User: admin (1 of 1, 0 complete) Password: Summer2024! (2 of 3 complete)
ACCOUNT FOUND: [ssh] Host: 10.0.0.5 User: admin Password: Summer2024! [SUCCESS]
''', dict(min=1, max=1, mention=["admin", "ssh"], sev={"credential": "CRITICAL"}, target="10.0.0.5",
          none=["Summer2024!"]))

# ── WPScan JSON ──────────────────────────────────────────────────────────────
S["wpscan_json"] = ("wpscan.json", '''{
  "banner": {"description": "WordPress Security Scanner by the WPScan Team", "version": "3.8.24",
             "authors": ["@_WPScan_", "@ethicalhack3r", "@erwan_lr", "@firefart"],
             "sponsor": "Sponsored by Automattic - https://automattic.com/"},
  "start_time": 1719223200,
  "start_memory": 51388416,
  "target_url": "http://blog.test/",
  "target_ip": "10.0.0.7",
  "effective_url": "http://blog.test/",
  "interesting_findings": [
    {"url": "http://blog.test/xmlrpc.php", "to_s": "XML-RPC seems to be enabled: http://blog.test/xmlrpc.php",
     "type": "xmlrpc", "found_by": "Direct Access (Aggressive Detection)", "confidence": 100,
     "confirmed_by": {}, "references": {"url": ["http://codex.wordpress.org/XML-RPC_Pingback_API"]},
     "interesting_entries": []},
    {"url": "http://blog.test/readme.html", "to_s": "WordPress readme found: http://blog.test/readme.html",
     "type": "readme", "found_by": "Direct Access (Aggressive Detection)", "confidence": 100,
     "confirmed_by": {}, "references": {}, "interesting_entries": []}
  ],
  "version": {"number": "5.2.1", "release_date": "2019-05-21", "status": "insecure",
              "found_by": "Rss Generator (Passive Detection)", "confidence": 100,
              "interesting_entries": ["http://blog.test/feed/, <generator>https://wordpress.org/?v=5.2.1</generator>"],
              "confirmed_by": {},
              "vulnerabilities": [
                {"title": "WordPress 5.0-5.2.2 - Authenticated Stored XSS in Shortcode Previews", "fixed_in": "5.2.3",
                 "references": {"cve": ["2019-16219"], "url": ["https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/"],
                                "wpvulndb": ["b4c0c5a0-8b3c-4f5b-9d1c-0d5c6d8f9e11"]}}
              ]},
  "main_theme": {"slug": "twentynineteen", "location": "http://blog.test/wp-content/themes/twentynineteen/",
                 "latest_version": "2.5", "last_updated": "2024-04-02T00:00:00.000Z", "outdated": true,
                 "style_name": "Twenty Nineteen", "vulnerabilities": [],
                 "version": {"number": "1.4", "confidence": 80, "found_by": "Css Style In Homepage (Passive Detection)"}},
  "plugins": {
    "contact-form-7": {"slug": "contact-form-7", "location": "http://blog.test/wp-content/plugins/contact-form-7/",
                       "latest_version": "5.9.5", "last_updated": "2024-05-01T00:00:00.000Z", "outdated": true,
                       "vulnerabilities": [
                         {"title": "Contact Form 7 < 5.3.2 - Unrestricted File Upload", "fixed_in": "5.3.2",
                          "references": {"cve": ["2020-35489"],
                                         "url": ["https://www.getastra.com/blog/911/plugin-exploit/contact-form-7-unrestricted-file-upload-vulnerability/"],
                                         "wpvulndb": ["7391118e-eef5-4ff8-a8ea-f6b65f442c63"]}}
                       ],
                       "version": {"number": "5.1.1", "confidence": 80, "found_by": "Readme - Stable Tag (Aggressive Detection)"}}
  },
  "users": {"admin": {"id": null, "slug": "admin", "found_by": "Author Posts - Author Pattern (Passive Detection)",
                      "confidence": 100}},
  "vuln_api": {"plan": "free", "requests_done_during_scan": 2, "requests_remaining": 23},
  "stop_time": 1719223260,
  "elapsed": 60,
  "requests_done": 180
}
''', dict(min=7, mention=["XML-RPC", "readme", "5.2.1", "Contact Form 7", "admin", "twentynineteen"],
          sev={"Unrestricted File Upload": "HIGH", "Shortcode": "HIGH"}, target="blog.test"))

# ── Nuclei ───────────────────────────────────────────────────────────────────
S["nuclei_console"] = ("nuclei.txt", '''
                     __     _
   ____  __  _______/ /__  (_)
  / __ \\/ / / / ___/ / _ \\/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\\__,_/\\___/_/\\___/_/   v3.1.0

\t\tprojectdiscovery.io

[INF] Current nuclei version: v3.1.0 (latest)
[INF] Templates loaded for current scan: 7812
[INF] Targets loaded for current scan: 1
[CVE-2021-41773] [http] [critical] http://shop.test/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd
[apache-detect] [http] [info] http://shop.test ["Apache/2.4.49 (Unix)"]
[http-missing-security-headers:x-frame-options] [http] [info] http://shop.test
[git-config] [http] [medium] http://shop.test/.git/config
[INF] Scan completed in 2m. 4 matches found.
''', dict(min=4, mention=["CVE-2021-41773", "git-config"], sev={"CVE-2021-41773": "CRITICAL", "git-config": "MEDIUM"},
          target="shop.test"))

S["nuclei_jsonl"] = ("nuclei.jsonl", '''{"template":"http/cves/2021/CVE-2021-41773.yaml","template-id":"CVE-2021-41773","template-path":"/root/nuclei-templates/http/cves/2021/CVE-2021-41773.yaml","info":{"name":"Apache 2.4.49 - Path Traversal and Remote Code Execution","author":["daffainfo","666asd"],"tags":["cve","cve2021","lfi","apache","rce","kev"],"description":"A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root.","reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],"severity":"critical","metadata":{"verified":true},"classification":{"cve-id":["cve-2021-41773"],"cwe-id":["cwe-22"],"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N","cvss-score":7.5},"remediation":"Update to Apache HTTP Server 2.4.51 or later."},"type":"http","host":"http://shop.test","matched-at":"http://shop.test/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd","ip":"10.0.0.5","timestamp":"2025-06-24T10:00:00.000000000+05:30","matcher-status":true}
{"template-id":"git-config","info":{"name":"Git Configuration - Detect","author":["pdteam"],"tags":["config","git","exposure"],"description":"Git configuration was detected via the pattern /.git/config and log file on passed URLs.","severity":"medium","classification":{"cwe-id":["cwe-200"],"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","cvss-score":5.3}},"type":"http","host":"http://shop.test","matched-at":"http://shop.test/.git/config","ip":"10.0.0.5","timestamp":"2025-06-24T10:00:02.000000000+05:30","matcher-status":true}
{"template-id":"apache-detect","info":{"name":"Apache Detection","author":["philippedelteil"],"tags":["tech","apache"],"severity":"info"},"type":"http","host":"http://shop.test","matched-at":"http://shop.test","extracted-results":["Apache/2.4.49 (Unix)"],"ip":"10.0.0.5","timestamp":"2025-06-24T10:00:01.000000000+05:30","matcher-status":true}
''', dict(min=3, mention=["CVE-2021-41773", "Git Configuration"], sev={"Path Traversal": "CRITICAL", "Git Configuration": "MEDIUM"},
          target="shop.test"))

# ── TLS scanners ─────────────────────────────────────────────────────────────
S["sslscan"] = ("sslscan.txt", '''Version: 2.0.15-static
OpenSSL 1.1.1u-dev  xx XXX xxxx

Connected to 10.0.0.5

Testing SSL server shop.test on port 443 using SNI name shop.test

  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     disabled
TLSv1.0   enabled
TLSv1.1   enabled
TLSv1.2   enabled
TLSv1.3   disabled

  TLS Fallback SCSV:
Server supports TLS Fallback SCSV

  TLS renegotiation:
Session renegotiation not supported

  TLS Compression:
Compression disabled

  Heartbleed:
TLSv1.2 not vulnerable to heartbleed
TLSv1.1 not vulnerable to heartbleed
TLSv1.0 not vulnerable to heartbleed

  Supported Server Cipher(s):
Preferred TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384   Curve 25519 DHE 253
Accepted  TLSv1.2  112 bits  DES-CBC3-SHA
Preferred TLSv1.0  128 bits  RC4-SHA

  SSL Certificate:
Signature Algorithm: sha256WithRSAEncryption
RSA Key Strength:    2048

Subject:  shop.test
Issuer:   R3

Not valid before: Jan  1 00:00:00 2024 GMT
Not valid after:  Mar 31 23:59:59 2024 GMT
''', dict(min=2, mention=["TLSv1.0", "DES-CBC3-SHA"], target="shop.test", none=["heartbleed"]))

S["testssl_csv"] = ("testssl.csv", '''"id","fqdn/ip","port","severity","finding","cve","cwe"
"service","shop.test/10.0.0.5","443","INFO","HTTP","",""
"SSLv2","shop.test/10.0.0.5","443","OK","not offered","",""
"TLS1","shop.test/10.0.0.5","443","LOW","offered (deprecated)","",""
"TLS1_1","shop.test/10.0.0.5","443","LOW","offered (deprecated)","",""
"heartbleed","shop.test/10.0.0.5","443","OK","not vulnerable, no heartbeat extension","CVE-2014-0160","CWE-119"
"SWEET32","shop.test/10.0.0.5","443","LOW","uses 64 bit block ciphers","CVE-2016-2183 CVE-2016-6329","CWE-327"
"BEAST","shop.test/10.0.0.5","443","LOW","VULNERABLE -- but also supports higher protocols  TLSv1.1 TLSv1.2 (likely mitigated)","CVE-2011-3389","CWE-20"
"cert_expirationStatus","shop.test/10.0.0.5","443","CRITICAL","expired","",""
''', dict(min=4, max=5, mention=["SWEET32", "TLS1", "expired"], sev={"SWEET32": "LOW", "expir": "CRITICAL"},
          target="shop.test", none=["heartbleed", "SSLv2", "service"]))

S["testssl_json"] = ("testssl.json", '''[
  {"id": "service", "ip": "shop.test/10.0.0.5", "port": "443", "severity": "INFO", "finding": "HTTP"},
  {"id": "SSLv2", "ip": "shop.test/10.0.0.5", "port": "443", "severity": "OK", "finding": "not offered"},
  {"id": "TLS1", "ip": "shop.test/10.0.0.5", "port": "443", "severity": "LOW", "finding": "offered (deprecated)"},
  {"id": "heartbleed", "ip": "shop.test/10.0.0.5", "port": "443", "severity": "OK", "cve": "CVE-2014-0160", "cwe": "CWE-119", "finding": "not vulnerable, no heartbeat extension"},
  {"id": "SWEET32", "ip": "shop.test/10.0.0.5", "port": "443", "severity": "LOW", "cve": "CVE-2016-2183 CVE-2016-6329", "cwe": "CWE-327", "finding": "uses 64 bit block ciphers"},
  {"id": "cert_expirationStatus", "ip": "shop.test/10.0.0.5", "port": "443", "severity": "CRITICAL", "finding": "expired"}
]
''', dict(min=3, max=3, mention=["SWEET32", "TLS1", "expired"], sev={"SWEET32": "LOW", "expir": "CRITICAL"},
          target="shop.test", none=["heartbleed", "SSLv2", "service"]))

# ── SMB / network enumeration ───────────────────────────────────────────────
S["enum4linux"] = ("enum4linux.txt", '''Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Jun 24 10:00:00 2025

 =========================================( Target Information )=========================================

Target ........... 10.0.0.8
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''

 ====================================( Session Check on 10.0.0.8 )====================================


[+] Server 10.0.0.8 allows sessions using username '', password ''

 =================================( Share Enumeration on 10.0.0.8 )=================================

\tSharename       Type      Comment
\t---------       ----      -------
\tprint$          Disk      Printer Drivers
\tpublic          Disk      Public share
\tIPC$            IPC       IPC Service (Samba 4.7.6-Ubuntu)

[+] Attempting to map shares on 10.0.0.8

//10.0.0.8/print$\tMapping: DENIED Listing: N/A Writing: N/A
//10.0.0.8/public\tMapping: OK Listing: OK Writing: N/A
''', dict(min=2, mention=["null session", "public"], target="10.0.0.8"))

S["masscan"] = ("masscan.txt", '''Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2025-06-24 10:00:00 GMT
Initiating SYN Stealth Scan
Scanning 256 hosts [65535 ports/host]
Discovered open port 23/tcp on 10.0.0.5
Discovered open port 443/tcp on 10.0.0.5
Discovered open port 22/tcp on 10.0.0.6
''', dict(min=3, max=3, mention=["Telnet", "22/tcp"], sev={"Telnet": "HIGH", "Open ports on 10.0.0.5": "INFO"}))

# ── Other scanner exports ────────────────────────────────────────────────────
S["nessus_csv"] = ("nessus_export.csv", '''Plugin ID,CVE,CVSS v2.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,See Also,Plugin Output,CVSS v3.0 Base Score
42873,CVE-2016-2183,5.0,Medium,10.0.0.5,tcp,443,SSL Medium Strength Cipher Suites Supported (SWEET32),The remote service supports the use of medium strength SSL ciphers.,The remote host supports the use of SSL ciphers that offer medium strength encryption.,Reconfigure the affected application if possible to avoid use of medium strength ciphers.,https://sweet32.info,"  Medium Strength Ciphers (> 64-bit and < 112-bit key, or 3DES)
    DES-CBC3-SHA",7.5
104743,,6.1,Medium,10.0.0.5,tcp,443,TLS Version 1.0 Protocol Detection,The remote service encrypts traffic using an older version of TLS.,The remote service accepts connections encrypted using TLS 1.0.,Enable support for TLS 1.2 and 1.3 and disable support for TLS 1.0.,,TLSv1 is enabled and the server supports at least one cipher.,6.5
19506,,,None,10.0.0.5,tcp,0,Nessus Scan Information,This plugin displays information about the Nessus scan.,This plugin displays information about the Nessus scan.,n/a,,Nessus version : 10.6.0,
''', dict(min=3, max=3, mention=["SWEET32", "TLS Version 1.0"], sev={"SWEET32": "MEDIUM", "Scan Information": "INFO"},
          target="10.0.0.5"))

S["burp_xml"] = ("burp_issues.xml", '''<?xml version="1.0"?>
<!DOCTYPE issues [
<!ELEMENT issues (issue*)>
<!ATTLIST issues burpVersion CDATA "">
<!ATTLIST issues exportTime CDATA "">
]>
<issues burpVersion="2023.10.3.4" exportTime="Tue Jun 24 10:00:00 IST 2025">
  <issue>
    <serialNumber>5716395585457373184</serialNumber>
    <type>1049088</type>
    <name>SQL injection</name>
    <host ip="34.249.203.140">https://ginandjuice.shop</host>
    <path><![CDATA[/catalog/filter]]></path>
    <location><![CDATA[/catalog/filter [category parameter]]]></location>
    <severity>High</severity>
    <confidence>Firm</confidence>
    <issueBackground><![CDATA[<p>SQL injection vulnerabilities arise when user-controllable data is incorporated into database SQL queries in an unsafe manner.</p>]]></issueBackground>
    <remediationBackground><![CDATA[<p>The most effective way to prevent SQL injection attacks is to use parameterized queries (also known as prepared statements) for all database access.</p>]]></remediationBackground>
    <vulnerabilityClassifications><![CDATA[<ul>
<li><a href="https://cwe.mitre.org/data/definitions/89.html">CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')</a></li>
</ul>]]></vulnerabilityClassifications>
    <issueDetail><![CDATA[The <b>category</b> parameter appears to be vulnerable to SQL injection attacks.]]></issueDetail>
  </issue>
  <issue>
    <serialNumber>1234567890123456789</serialNumber>
    <type>5245344</type>
    <name>Frameable response (potential Clickjacking)</name>
    <host ip="34.249.203.140">https://ginandjuice.shop</host>
    <path><![CDATA[/]]></path>
    <location><![CDATA[/]]></location>
    <severity>Information</severity>
    <confidence>Firm</confidence>
    <issueBackground><![CDATA[<p>If a page fails to set an appropriate X-Frame-Options or Content-Security-Policy HTTP header, it might be possible for a page controlled by an attacker to load it within an iframe.</p>]]></issueBackground>
    <remediationBackground><![CDATA[<p>To effectively prevent framing attacks, the application should return a response header with the name X-Frame-Options.</p>]]></remediationBackground>
    <vulnerabilityClassifications><![CDATA[<ul>
<li><a href="https://cwe.mitre.org/data/definitions/693.html">CWE-693: Protection Mechanism Failure</a></li>
</ul>]]></vulnerabilityClassifications>
  </issue>
</issues>
''', dict(min=2, max=2, mention=["SQL injection", "Clickjacking"], sev={"SQL injection": "HIGH", "Frameable": "INFO"},
          target="ginandjuice.shop"))

S["zap_xml"] = ("zap_report.xml", '''<?xml version="1.0"?>
<OWASPZAPReport programName="ZAP" version="2.14.0" generated="Tue, 24 Jun 2025 10:00:00">
\t<site name="http://shop.test" host="shop.test" port="80" ssl="false">
\t\t<alerts>
\t\t\t<alertitem>
\t\t\t\t<pluginid>40018</pluginid>
\t\t\t\t<alertRef>40018</alertRef>
\t\t\t\t<alert>SQL Injection</alert>
\t\t\t\t<name>SQL Injection</name>
\t\t\t\t<riskcode>3</riskcode>
\t\t\t\t<confidence>2</confidence>
\t\t\t\t<riskdesc>High (Medium)</riskdesc>
\t\t\t\t<confidencedesc>Medium</confidencedesc>
\t\t\t\t<desc>&lt;p&gt;SQL injection may be possible.&lt;/p&gt;</desc>
\t\t\t\t<instances>
\t\t\t\t\t<instance>
\t\t\t\t\t\t<uri>http://shop.test/product.php?id=1</uri>
\t\t\t\t\t\t<method>GET</method>
\t\t\t\t\t\t<param>id</param>
\t\t\t\t\t\t<attack>1 AND 1=1 -- </attack>
\t\t\t\t\t\t<evidence></evidence>
\t\t\t\t\t\t<otherinfo></otherinfo>
\t\t\t\t\t</instance>
\t\t\t\t</instances>
\t\t\t\t<count>1</count>
\t\t\t\t<solution>&lt;p&gt;Use prepared statements with parameterized queries.&lt;/p&gt;</solution>
\t\t\t\t<otherinfo></otherinfo>
\t\t\t\t<reference>&lt;p&gt;https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html&lt;/p&gt;</reference>
\t\t\t\t<cweid>89</cweid>
\t\t\t\t<wascid>19</wascid>
\t\t\t\t<sourceid>1</sourceid>
\t\t\t</alertitem>
\t\t\t<alertitem>
\t\t\t\t<pluginid>10020</pluginid>
\t\t\t\t<alertRef>10020-1</alertRef>
\t\t\t\t<alert>Missing Anti-clickjacking Header</alert>
\t\t\t\t<name>Missing Anti-clickjacking Header</name>
\t\t\t\t<riskcode>2</riskcode>
\t\t\t\t<confidence>2</confidence>
\t\t\t\t<riskdesc>Medium (Medium)</riskdesc>
\t\t\t\t<confidencedesc>Medium</confidencedesc>
\t\t\t\t<desc>&lt;p&gt;The response does not protect against 'ClickJacking' attacks.&lt;/p&gt;</desc>
\t\t\t\t<instances>
\t\t\t\t\t<instance>
\t\t\t\t\t\t<uri>http://shop.test/</uri>
\t\t\t\t\t\t<method>GET</method>
\t\t\t\t\t\t<param>x-frame-options</param>
\t\t\t\t\t\t<attack></attack>
\t\t\t\t\t\t<evidence></evidence>
\t\t\t\t\t\t<otherinfo></otherinfo>
\t\t\t\t\t</instance>
\t\t\t\t</instances>
\t\t\t\t<count>1</count>
\t\t\t\t<solution>&lt;p&gt;Ensure the X-Frame-Options HTTP header or the frame-ancestors directive of CSP is set.&lt;/p&gt;</solution>
\t\t\t\t<otherinfo></otherinfo>
\t\t\t\t<reference></reference>
\t\t\t\t<cweid>1021</cweid>
\t\t\t\t<wascid>15</wascid>
\t\t\t\t<sourceid>1</sourceid>
\t\t\t</alertitem>
\t\t</alerts>
\t</site>
</OWASPZAPReport>
''', dict(min=2, max=2, mention=["SQL Injection", "Anti-clickjacking"], sev={"SQL Injection": "HIGH", "Anti-clickjacking": "MEDIUM"},
          target="shop.test"))

S["zap_json"] = ("zap_report.json", '''{
\t"@programName": "ZAP",
\t"@version": "2.14.0",
\t"@generated": "Tue, 24 Jun 2025 10:00:00",
\t"site":[
\t\t{
\t\t\t"@name": "http://shop.test",
\t\t\t"@host": "shop.test",
\t\t\t"@port": "80",
\t\t\t"@ssl": "false",
\t\t\t"alerts": [
\t\t\t\t{
\t\t\t\t\t"pluginid": "40018",
\t\t\t\t\t"alertRef": "40018",
\t\t\t\t\t"alert": "SQL Injection",
\t\t\t\t\t"name": "SQL Injection",
\t\t\t\t\t"riskcode": "3",
\t\t\t\t\t"confidence": "2",
\t\t\t\t\t"riskdesc": "High (Medium)",
\t\t\t\t\t"desc": "<p>SQL injection may be possible.</p>",
\t\t\t\t\t"instances":[
\t\t\t\t\t\t{"uri": "http://shop.test/product.php?id=1", "method": "GET", "param": "id", "attack": "1 AND 1=1 -- ", "evidence": "", "otherinfo": ""}
\t\t\t\t\t],
\t\t\t\t\t"count": "1",
\t\t\t\t\t"solution": "<p>Use prepared statements with parameterized queries.</p>",
\t\t\t\t\t"otherinfo": "",
\t\t\t\t\t"reference": "<p>https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html</p>",
\t\t\t\t\t"cweid": "89",
\t\t\t\t\t"wascid": "19",
\t\t\t\t\t"sourceid": "1"
\t\t\t\t},
\t\t\t\t{
\t\t\t\t\t"pluginid": "10020",
\t\t\t\t\t"alertRef": "10020-1",
\t\t\t\t\t"alert": "Missing Anti-clickjacking Header",
\t\t\t\t\t"name": "Missing Anti-clickjacking Header",
\t\t\t\t\t"riskcode": "2",
\t\t\t\t\t"confidence": "2",
\t\t\t\t\t"riskdesc": "Medium (Medium)",
\t\t\t\t\t"desc": "<p>The response does not protect against 'ClickJacking' attacks.</p>",
\t\t\t\t\t"instances":[
\t\t\t\t\t\t{"uri": "http://shop.test/", "method": "GET", "param": "x-frame-options", "attack": "", "evidence": "", "otherinfo": ""}
\t\t\t\t\t],
\t\t\t\t\t"count": "1",
\t\t\t\t\t"solution": "<p>Ensure the X-Frame-Options HTTP header or the frame-ancestors directive of CSP is set.</p>",
\t\t\t\t\t"otherinfo": "",
\t\t\t\t\t"reference": "",
\t\t\t\t\t"cweid": "1021",
\t\t\t\t\t"wascid": "15",
\t\t\t\t\t"sourceid": "1"
\t\t\t\t}
\t\t\t]
\t\t}
\t]
}
''', dict(min=2, max=2, mention=["SQL Injection", "Anti-clickjacking"], sev={"SQL Injection": "HIGH", "Anti-clickjacking": "MEDIUM"},
          target="shop.test"))

S["openvas_xml"] = ("openvas_report.xml", '''<report id="0a1b2c3d-0000-4000-8000-000000000001" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5" extension="xml" content_type="text/xml">
<owner><name>admin</name></owner><name>2025-06-24T10:00:00Z</name>
<report id="0a1b2c3d-0000-4000-8000-000000000001">
<gmp><version>22.4</version></gmp>
<scan_run_status>Done</scan_run_status>
<results start="1" max="100">
<result id="11111111-0000-4000-8000-000000000001">
<name>SSL/TLS: Report Vulnerable Cipher Suites for HTTPS</name>
<owner><name>admin</name></owner>
<host>10.0.0.5<asset asset_id="aaaa"/><hostname>shop.test</hostname></host>
<port>443/tcp</port>
<nvt oid="1.3.6.1.4.1.25623.1.0.108031">
<type>nvt</type>
<name>SSL/TLS: Report Vulnerable Cipher Suites for HTTPS</name>
<family>SSL and TLS</family>
<cvss_base>7.5</cvss_base>
<severities score="7.5"><severity type="cvss_base_v3"><origin/><date/><score>7.5</score><value>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</value></severity></severities>
<tags>cvss_base_vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N|summary=This routine reports all SSL/TLS cipher suites accepted by a service where attack vectors exists only on HTTPS services.|insight=These rules are applied for the evaluation of the vulnerable cipher suites: 64-bit block cipher 3DES vulnerable to the SWEET32 attack (CVE-2016-2183).|affected=|impact=|solution=The configuration of this services should be changed so that it does not accept the listed cipher suites anymore.|vuldetect=Checks previous collected cipher suites.|solution_type=Mitigation</tags>
<solution type="Mitigation">The configuration of this services should be changed so that it does not accept the listed cipher suites anymore.</solution>
<refs><ref type="cve" id="CVE-2016-2183"/><ref type="cve" id="CVE-2016-6329"/><ref type="url" id="https://sweet32.info/"/></refs>
</nvt>
<scan_nvt_version/>
<threat>High</threat>
<severity>7.5</severity>
<qod><value>98</value><type>remote_app</type></qod>
<description>'Vulnerable' cipher suites accepted by this service via the TLSv1.2 protocol:

TLS_RSA_WITH_3DES_EDE_CBC_SHA (SWEET32)</description>
</result>
<result id="11111111-0000-4000-8000-000000000002">
<name>OS Detection Consolidation and Reporting</name>
<host>10.0.0.5<hostname>shop.test</hostname></host>
<port>general/tcp</port>
<nvt oid="1.3.6.1.4.1.25623.1.0.105937"><type>nvt</type><name>OS Detection Consolidation and Reporting</name><family>Product detection</family><cvss_base>0.0</cvss_base>
<tags>cvss_base_vector=AV:N/AC:L/Au:N/C:N/I:N/A:N|summary=This script consolidates the OS information detected by several VTs.|solution_type=</tags><refs/></nvt>
<threat>Log</threat>
<severity>0.0</severity>
<qod><value>80</value><type>remote_banner</type></qod>
<description>Best matching OS: Ubuntu 18.04</description>
</result>
</results>
</report>
</report>
''', dict(min=1, max=2, mention=["Vulnerable Cipher Suites"], sev={"Cipher Suites": "HIGH"}, target="10.0.0.5"))

S["openvas_csv"] = ("openvas_report.csv", '''IP,Hostname,Port,Port Protocol,CVSS,Severity,QoD,Solution Type,NVT Name,Summary,Specific Result,NVT OID,CVEs,Task ID,Task Name,Timestamp,Result ID,Impact,Solution,Affected Software/OS,Vulnerability Insight,Vulnerability Detection Method,Product Detection Result,BIDs,CERTs,Other References
10.0.0.5,shop.test,443,tcp,7.5,High,98,Mitigation,SSL/TLS: Report Vulnerable Cipher Suites for HTTPS,This routine reports all SSL/TLS cipher suites accepted by a service where attack vectors exists only on HTTPS services.,"'Vulnerable' cipher suites accepted by this service via the TLSv1.2 protocol:
TLS_RSA_WITH_3DES_EDE_CBC_SHA (SWEET32)",1.3.6.1.4.1.25623.1.0.108031,"CVE-2016-2183,CVE-2016-6329",t1,Web scan,2025-06-24T10:00:00Z,r1,,The configuration of this services should be changed so that it does not accept the listed cipher suites anymore.,,,Checks previous collected cipher suites.,,,,https://sweet32.info/
10.0.0.5,shop.test,80,tcp,4.3,Medium,99,Mitigation,Cleartext Transmission of Sensitive Information via HTTP,The host / application transmits sensitive information (username / passwords) in cleartext via HTTP.,"The following input fields were identified (URL:input name):
http://shop.test/login:password",1.3.6.1.4.1.25623.1.0.108440,,t1,Web scan,2025-06-24T10:00:00Z,r2,,Enforce the transmission of sensitive data via an encrypted SSL/TLS connection.,,,,,,,
''', dict(min=2, max=2, mention=["Vulnerable Cipher Suites", "Cleartext"], sev={"Cipher Suites": "HIGH", "Cleartext": "MEDIUM"},
          target="10.0.0.5"))

S["trivy_table"] = ("trivy.txt", '''
shop:1.0 (debian 11.6)
======================
Total: 2 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 1)

┌──────────┬────────────────┬──────────┬────────┬─────────────────────────┬─────────────────────────┬──────────────────────────────────────────────────────────┐
│ Library  │ Vulnerability  │ Severity │ Status │    Installed Version    │      Fixed Version      │                          Title                           │
├──────────┼────────────────┼──────────┼────────┼─────────────────────────┼─────────────────────────┼──────────────────────────────────────────────────────────┤
│ openssl  │ CVE-2023-0286  │ HIGH     │ fixed  │ 1.1.1n-0+deb11u3        │ 1.1.1n-0+deb11u4        │ openssl: X.400 address type confusion in X.509           │
│          │                │          │        │                         │                         │ GeneralName                                              │
│          │                │          │        │                         │                         │ https://avd.aquasec.com/nvd/cve-2023-0286                │
├──────────┼────────────────┼──────────┼────────┼─────────────────────────┼─────────────────────────┼──────────────────────────────────────────────────────────┤
│ zlib1g   │ CVE-2022-37434 │ CRITICAL │ fixed  │ 1:1.2.11.dfsg-2+deb11u1 │ 1:1.2.11.dfsg-2+deb11u2 │ zlib: heap-based buffer over-read and overflow in        │
│          │                │          │        │                         │                         │ inflate() in inflate.c via a...                          │
│          │                │          │        │                         │                         │ https://avd.aquasec.com/nvd/cve-2022-37434               │
└──────────┴────────────────┴──────────┴────────┴─────────────────────────┴─────────────────────────┴──────────────────────────────────────────────────────────┘
''', dict(min=2, max=2, mention=["CVE-2023-0286", "CVE-2022-37434"], sev={"zlib": "CRITICAL", "openssl": "HIGH"}))

S["qualys_xml"] = ("qualys_scan.xml", '''<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE SCAN SYSTEM "https://qualysguard.qg2.apps.qualys.com/scan-1.dtd">
<SCAN value="scan/1719223200.12345">
<HEADER>
<KEY value="USERNAME">auditor</KEY>
<KEY value="SCAN_DATE">2025-06-24T10:00:00Z</KEY>
<KEY value="TITLE"><![CDATA[Web scan]]></KEY>
</HEADER>
<IP value="10.0.0.5" name="web01">
<OS><![CDATA[Ubuntu 18.04]]></OS>
<VULNS>
<CAT value="General remote services" port="443" protocol="tcp">
<VULN number="38657" severity="3">
<TITLE><![CDATA[Birthday attacks against TLS ciphers with 64bit block size vulnerability (Sweet32)]]></TITLE>
<CVE_ID_LIST><CVE_ID><ID><![CDATA[CVE-2016-2183]]></ID><URL><![CDATA[http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2183]]></URL></CVE_ID></CVE_ID_LIST>
<CVSS_BASE>5.0</CVSS_BASE>
<CVSS3_BASE>7.5</CVSS3_BASE>
<DIAGNOSIS><![CDATA[Legacy block ciphers having block size of 64 bits are vulnerable to a practical collision attack.]]></DIAGNOSIS>
<CONSEQUENCE><![CDATA[A man-in-the-middle attacker could recover plaintext.]]></CONSEQUENCE>
<SOLUTION><![CDATA[Disable ciphers with a 64 bit block size.]]></SOLUTION>
<RESULT><![CDATA[DES-CBC3-SHA]]></RESULT>
</VULN>
</CAT>
</VULNS>
</IP>
</SCAN>
''', dict(min=1, max=1, mention=["Sweet32"], sev={"Sweet32": "MEDIUM"}, target="10.0.0.5"))
