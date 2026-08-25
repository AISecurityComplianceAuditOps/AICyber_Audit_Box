# -*- coding: utf-8 -*-
import json

controls = []

def to_title_case(s):
    exceptions = ["for", "and", "of", "in", "with", "to", "on", "from", "after", "or", "by", "against", "about"]
    parts = s.split(" ")
    title_parts = []
    for idx, p in enumerate(parts):
        clean_p = p.replace("(", "").replace(")", "").lower()
        if idx == 0 or idx == len(parts) - 1 or clean_p not in exceptions:
            if p.startswith("("):
                title_parts.append("(" + p[1:].capitalize())
            else:
                title_parts.append(p.capitalize())
        else:
            title_parts.append(p.lower())
    return " ".join(title_parts)

# --- Clause 5: Organizational Controls (5.1 to 5.37) ---
c5_controls = [
    ("Policies for information security", "📄", "Verify if information security policies are defined, approved, and communicated.", "Approved Information Security Policy Document.", ["Risk Assessment", "General Security Policy"], "HIGH"),
    ("Information security roles and responsibilities", "👥", "Verify that information security roles and responsibilities are defined and allocated.", "Org chart, role descriptions with security duties.", ["Risk Assessment", "General Security Policy"], "MEDIUM"),
    ("Segregation of duties", "🔀", "Verify that conflicting duties and areas of responsibility are segregated.", "Segregation of duties matrix, authorization logs.", ["Risk Assessment", "General Security Policy"], "HIGH"),
    ("Management responsibilities", "👔", "Verify management requires employees to apply security in accordance with established policies.", "Management meeting minutes, policy sign-offs.", ["Risk Assessment", "General Security Policy"], "MEDIUM"),
    ("Contact with authorities", "📞", "Verify that contact with relevant authorities is maintained.", "Procedure for contacting authorities, contact list.", ["Incident Management Policy", "General Security Policy"], "LOW"),
    ("Contact with special interest groups", "🤝", "Verify contact with special interest groups or security associations is maintained.", "List of memberships, participation records.", ["General Security Policy"], "LOW"),
    ("Threat intelligence", "📡", "Verify that threat intelligence is collected, analyzed, and acted upon.", "Threat intelligence feeds, vulnerability reports, actions taken.", ["Risk Assessment", "General Security Policy"], "MEDIUM"),
    ("Information security in project management", "🏗️", "Verify information security is integrated into project management.", "Project planning docs, security requirements in projects.", ["General Security Policy", "Development / Secure Coding Policy"], "MEDIUM"),
    ("Inventory of information and other associated assets", "📋", "Verify that an inventory of information and other associated assets is maintained.", "Asset inventory register.", ["Asset Management Policy"], "HIGH"),
    ("Acceptable use of information and other associated assets", "💻", "Verify that rules for acceptable use of assets are defined and implemented.", "Acceptable Use Policy (AUP) signed by employees.", ["Asset Management Policy", "General Security Policy"], "MEDIUM"),
    ("Return of assets", "🔄", "Verify that employees and external users return all assets upon termination.", "Offboarding checklist, asset return logs.", ["Asset Management Policy", "HR / People Security Policy"], "MEDIUM"),
    ("Classification of information", "🏷️", "Verify that information is classified in accordance with security requirements.", "Data Classification Policy, classified document samples.", ["Asset Management Policy"], "HIGH"),
    ("Labelling of information", "🏷️", "Verify that procedures for labelling information are developed and implemented.", "Information labelling guidelines, screenshots of labelled data.", ["Asset Management Policy"], "MEDIUM"),
    ("Information transfer", "📤", "Verify that rules, procedures, and agreements for information transfer are in place.", "Data Transfer Policy, secure transfer logs, NDAs.", ["Asset Management Policy", "Technology / IT Security Policy"], "HIGH"),
    ("Access control", "🔐", "Verify rules to control physical and logical access to information are established.", "Access Control Policy and rules to control physical and/or logical access (such as authorization request procedures, visitor sign-ins, badges, keycard systems, or escort rules).", ["Access Control Policy", "Physical Security Policy"], "CRITICAL"),
    ("Identity management", "🆔", "Verify the full lifecycle of identities (user accounts) is managed.", "Identity management procedure, user list, joiner/leaver records.", ["Access Control Policy"], "CRITICAL"),
    ("Authentication information", "🔑", "Verify allocation and management of authentication information (passwords, keys).", "Password policy, credentials management procedure.", ["Access Control Policy"], "CRITICAL"),
    ("Access rights", "👁️", "Verify that access rights are provisioned, reviewed, and modified.", "User access review reports, access modification logs.", ["Access Control Policy"], "CRITICAL"),
    ("Information security in supplier relationships", "🤝", "Verify processes to mitigate risks associated with supplier access to assets.", "Supplier Security Policy, supplier risk assessments.", ["Supplier / Third Party Policy"], "HIGH"),
    ("Addressing information security within supplier agreements", "📝", "Verify that relevant security requirements are established in supplier contracts.", "Supplier contracts/agreements with security clauses.", ["Supplier / Third Party Policy"], "HIGH"),
    ("Managing information security in the ICT supply chain", "🚚", "Verify security requirements are defined and monitored down the supply chain.", "Supply chain risk assessment, supplier compliance logs.", ["Supplier / Third Party Policy", "Technology / IT Security Policy"], "MEDIUM"),
    ("Monitoring, review and change management of supplier services", "📊", "Verify that supplier service delivery is regularly monitored and reviewed.", "Supplier review reports, SLA monitoring logs.", ["Supplier / Third Party Policy"], "MEDIUM"),
    ("Information security for use of cloud services", "☁️", "Verify that security requirements for cloud services are established.", "Cloud Security Policy, cloud provider assessments.", ["Technology / IT Security Policy", "Supplier / Third Party Policy"], "HIGH"),
    ("Information security incident management planning and preparation", "📅", "Verify processes to prepare for and manage security incidents.", "Incident Response Plan (IRP), roles and contact list.", ["Incident Management Policy"], "CRITICAL"),
    ("Assessment and decision on information security events", "⚖️", "Verify that security events are assessed to determine if they are incidents.", "Incident triage logs, classification guidelines.", ["Incident Management Policy"], "HIGH"),
    ("Response to information security incidents", "🚒", "Verify that information security incidents are responded to and managed.", "Incident ticket logs, post-incident reports.", ["Incident Management Policy"], "CRITICAL"),
    ("Learning from information security incidents", "🧠", "Verify that knowledge gained from incidents is used to prevent recurrence.", "Post-Incident Review (PIR) reports, updated procedures.", ["Incident Management Policy"], "MEDIUM"),
    ("Collection of evidence", "🗄️", "Verify that procedures are established for the collection and preservation of evidence.", "Forensics procedure, evidence chain of custody logs.", ["Incident Management Policy"], "MEDIUM"),
    ("Information security during disruption", "🌪️", "Verify information security continuity is planned and implemented during disruption.", "Business Continuity Plan (BCP), emergency response procedure.", ["Business Continuity Plan"], "HIGH"),
    ("Ict readiness for business continuity", "🖥️", "Verify that ICT systems readiness is planned, implemented, and tested.", "Disaster Recovery (DR) Plan, failover testing reports.", ["Business Continuity Plan"], "HIGH"),
    ("Legal, statutory, regulatory and contractual requirements", "⚖️", "Verify that all legal, statutory, regulatory and contractual requirements are identified.", "Compliance register, legal review reports.", ["Compliance / Legal Policy"], "HIGH"),
    ("Intellectual property rights", "🔬", "Verify that procedures to protect intellectual property rights are implemented.", "IP protection policy, license compliance checks.", ["Compliance / Legal Policy"], "MEDIUM"),
    ("Protection of records", "📂", "Verify that records are protected from loss, destruction, and unauthorized access.", "Records Retention Policy, secure backup configurations.", ["Compliance / Legal Policy", "Asset Management Policy"], "MEDIUM"),
    ("Privacy and protection of personally identifiable information (Pii)", "🔒", "Verify protection of PII according to applicable laws and regulations.", "Privacy Policy, PII inventory, DPA templates.", ["Compliance / Legal Policy", "General Security Policy"], "CRITICAL"),
    ("Independent review of information security", "🔍", "Verify that information security management is independently reviewed.", "Internal audit reports, external audit certificates.", ["General Security Policy", "Compliance / Legal Policy"], "HIGH"),
    ("Compliance with policies and standards for information security", "📏", "Verify regular review of compliance with policies and standards.", "Compliance scans, self-assessment checklists.", ["General Security Policy", "Compliance / Legal Policy"], "HIGH"),
    ("Documented operating procedures", "📚", "Verify that operating procedures for information processing are documented.", "Standard Operating Procedures (SOPs), system runbooks.", ["General Security Policy", "Technology / IT Security Policy"], "MEDIUM")
]

for idx, (name, icon, use_case, expected, scopes, severity) in enumerate(c5_controls, 1):
    code = f"5.{idx}"
    title_name = to_title_case(name)
    controls.append({
        "sl": idx,
        "standard": "ISO 27001",
        "category": "Clause 5 — Organizational Controls",
        "label": f"{title_name} ({code})",
        "icon": icon,
        "use_case": f"{code} {title_name}",
        "expected": expected,
        "format": "PDF",
        "prompt_hint": f"Verify compliance against {code} {title_name}. {use_case}",
        "scope_tags": scopes,
        "severity": severity,
        "finding": f"No documented evidence found for {code} ({title_name}).",
        "recommendation": f"Establish, document, and implement procedures to satisfy {code} ({title_name})."
    })

# --- Clause 6: People Controls (6.1 to 6.8) ---
c6_controls = [
    ("Screening", "🔎", "Verify background checks on all candidates for employment are conducted.", "Background check reports, screening policy.", ["HR / People Security Policy"], "MEDIUM"),
    ("Terms and conditions of employment", "📄", "Verify employment contracts state employee security responsibilities.", "Employment contract templates with security clauses.", ["HR / People Security Policy"], "MEDIUM"),
    ("Information security awareness, education and training", "🎓", "Verify that employees receive security training and awareness updates.", "Training logs, security awareness presentations.", ["HR / People Security Policy", "General Security Policy"], "MEDIUM"),
    ("Disciplinary process", "⚖️", "Verify a formal disciplinary process is established for security breaches.", "Disciplinary Policy, employee handbook.", ["HR / People Security Policy", "General Security Policy"], "LOW"),
    ("Responsibilities after termination or change of employment", "🚪", "Verify responsibilities for termination or change of employment remain defined.", "Termination policy, signed exit agreements.", ["HR / People Security Policy", "Access Control Policy"], "MEDIUM"),
    ("Confidentiality or non-disclosure agreements", "🤫", "Verify that NDAs reflecting security needs are signed by employees and contractors.", "Signed NDA files, NDA template.", ["HR / People Security Policy", "Supplier / Third Party Policy"], "HIGH"),
    ("Remote working", "🏠", "Verify security measures are implemented when working remotely.", "Remote Work Policy, VPN logs, MDM setup details.", ["HR / People Security Policy", "Technology / IT Security Policy"], "HIGH"),
    ("Information security event reporting", "📣", "Verify employees are required to report security events promptly.", "Event reporting procedure, report template, ticketing tool screenshots.", ["HR / People Security Policy", "Incident Management Policy"], "HIGH")
]

for idx, (name, icon, use_case, expected, scopes, severity) in enumerate(c6_controls, 1):
    sl_num = 37 + idx
    code = f"6.{idx}"
    title_name = to_title_case(name)
    controls.append({
        "sl": sl_num,
        "standard": "ISO 27001",
        "category": "Clause 6 — People Controls",
        "label": f"{title_name} ({code})",
        "icon": icon,
        "use_case": f"{code} {title_name}",
        "expected": expected,
        "format": "PDF",
        "prompt_hint": f"Verify compliance against {code} {title_name}. {use_case}",
        "scope_tags": scopes,
        "severity": severity,
        "finding": f"No documented evidence found for {code} ({title_name}).",
        "recommendation": f"Establish, document, and implement procedures to satisfy {code} ({title_name})."
    })

# --- Clause 7: Physical Controls (7.1 to 7.14) ---
c7_controls = [
    ("Physical security perimeters", "🏢", "Verify that physical security perimeters are defined and protected.", "Site map, physical security policy, perimeter control descriptions.", ["Physical Security Policy", "Access Control Policy"], "MEDIUM"),
    ("Physical entry", "🚪", "Verify secure physical entry controls protect offices and facilities.", "Physical entry controls and procedures (such as access cards, visitor logbooks, security desks, escorts, or equivalent entry restrictions).", ["Physical Security Policy", "Access Control Policy"], "MEDIUM"),
    ("Securing offices, rooms and facilities", "🔒", "Verify that physical security for offices, rooms, and facilities is designed.", "Office layouts, secure area procedures.", ["Physical Security Policy"], "MEDIUM"),
    ("Physical security monitoring", "📹", "Verify that secure facilities are monitored for unauthorized access.", "Physical security monitoring evidence (such as CCTV records, guard logs, or intrusion alarm reports).", ["Physical Security Policy"], "LOW"),
    ("Protecting against physical and environmental threats", "🔥", "Verify protection against natural disasters, fire, and power failures.", "UPS maintenance records, fire suppression inspection, threat assessment.", ["Physical Security Policy", "Business Continuity Plan"], "MEDIUM"),
    ("Working in secure areas", "🛠️", "Verify that rules for working in secure areas are designed and implemented.", "Secure area working rules, visitor access controls.", ["Physical Security Policy"], "LOW"),
    ("Clear desk and clear screen", "🖥️", "Verify that clear desk and clear screen rules are defined and enforced.", "Clear Desk / Clear Screen Policy, audit inspection records.", ["Physical Security Policy", "General Security Policy"], "LOW"),
    ("Equipment siting and protection", "🔌", "Verify that equipment is sited and protected to reduce hazards.", "Data center layout, equipment maintenance logs.", ["Physical Security Policy", "Technology / IT Security Policy"], "LOW"),
    ("Security of assets off-premises", "📦", "Verify security for off-premises assets (laptops, mobile devices).", "Offboarding logs, mobile device security guidelines.", ["Physical Security Policy", "Asset Management Policy"], "MEDIUM"),
    ("Storage media", "💾", "Verify storage media is managed through full lifecycle (handling, disposal).", "Media disposal logs, e-waste agreements, media destruction certificates.", ["Physical Security Policy", "Technology / IT Security Policy"], "HIGH"),
    ("Supporting utilities", "⚡", "Verify equipment is protected from power failures and utility disruptions.", "Generator test logs, redundant utility SLAs.", ["Physical Security Policy", "Business Continuity Plan"], "LOW"),
    ("Cabling security", "🔌", "Verify power and telecommunications cabling is protected.", "Server room cabling photos, cabling diagrams, security measures description.", ["Physical Security Policy", "Technology / IT Security Policy"], "LOW"),
    ("Equipment maintenance", "🔧", "Verify equipment is maintained correctly to ensure availability.", "Maintenance schedule, vendor service records.", ["Physical Security Policy", "Technology / IT Security Policy"], "LOW"),
    ("Secure disposal or re-use of equipment", "♻️", "Verify equipment containing storage media is securely disposed of.", "Decommissioning procedures, data sanitization logs.", ["Physical Security Policy", "Asset Management Policy"], "HIGH")
]

for idx, (name, icon, use_case, expected, scopes, severity) in enumerate(c7_controls, 1):
    sl_num = 45 + idx
    code = f"7.{idx}"
    title_name = to_title_case(name)
    controls.append({
        "sl": sl_num,
        "standard": "ISO 27001",
        "category": "Clause 7 — Physical Controls",
        "label": f"{title_name} ({code})",
        "icon": icon,
        "use_case": f"{code} {title_name}",
        "expected": expected,
        "format": "PDF",
        "prompt_hint": f"Verify compliance against {code} {title_name}. {use_case}",
        "scope_tags": scopes,
        "severity": severity,
        "finding": f"No documented evidence found for {code} ({title_name}).",
        "recommendation": f"Establish, document, and implement procedures to satisfy {code} ({title_name})."
    })

# --- Clause 8: Technological Controls (8.1 to 8.34) ---
c8_controls = [
    ("User endpoint devices", "📱", "Verify security controls (encryption, MDM) on endpoint devices.", "MDM policy, disk encryption status reports.", ["Technology / IT Security Policy", "General Security Policy"], "HIGH"),
    ("Privileged access rights", "⚡", "Verify allocation and use of privileged access rights is restricted.", "Privileged access review records, PAM configurations, or equivalent control logs.", ["Access Control Policy", "Technology / IT Security Policy"], "CRITICAL"),
    ("Information access restriction", "👁️", "Verify access to information is restricted according to access policy.", "Access control list (ACL) reviews, permissions configs.", ["Access Control Policy", "Technology / IT Security Policy"], "CRITICAL"),
    ("Access to source code", "💻", "Verify access to source code is restricted to authorized personnel.", "Git repository permission lists, code access policy.", ["Access Control Policy", "Development / Secure Coding Policy"], "HIGH"),
    ("Secure authentication", "🔑", "Verify secure authentication (MFA, password complexity) is enforced.", "Authentication configurations (such as MFA logs, password policy settings, or secure login rules).", ["Access Control Policy", "Technology / IT Security Policy"], "CRITICAL"),
    ("Capacity management", "📈", "Verify system resources usage is monitored and tuned.", "Capacity monitoring reports, server resource dashboards.", ["Technology / IT Security Policy"], "LOW"),
    ("Protection against malware", "🛡️", "Verify malware detection and prevention tools are implemented.", "Malware protection configurations (such as antivirus deployment details, EDR settings, or scan logs).", ["Technology / IT Security Policy"], "HIGH"),
    ("Management of technical vulnerabilities", "🔍", "Verify technical vulnerabilities are identified and remediated.", "Vulnerability management evidence (such as scanning reports, patch logs, or mitigation records).", ["Technology / IT Security Policy"], "HIGH"),
    ("Configuration management", "⚙️", "Verify system configurations (security baselines) are managed.", "Configuration management policy, baseline configs.", ["Technology / IT Security Policy"], "MEDIUM"),
    ("Information deletion", "🗑️", "Verify information is deleted when no longer required.", "Data retention schedule, data deletion records.", ["Technology / IT Security Policy", "Asset Management Policy"], "MEDIUM"),
    ("Data masking", "🎭", "Verify data masking is used to protect sensitive data.", "Data masking rules, test database configs.", ["Technology / IT Security Policy"], "MEDIUM"),
    ("Data leakage prevention", "🛡️", "Verify DLP measures are implemented for sensitive systems.", "Data leakage prevention configurations (such as DLP policies, tool settings, or alert logs).", ["Technology / IT Security Policy"], "HIGH"),
    ("Information backup", "💾", "Verify backups of information and software are taken and tested.", "Backup logs, restore test reports, or equivalent verification.", ["Technology / IT Security Policy", "Business Continuity Plan"], "CRITICAL"),
    ("Redundancy of information processing facilities", "🔄", "Verify redundancy is built into information systems.", "High availability config, redundant network paths.", ["Technology / IT Security Policy", "Business Continuity Plan"], "HIGH"),
    ("Logging", "📝", "Verify event logs recording user activities, anomalies are produced.", "System logging evidence (such as SIEM configs, log reports, or retention policies).", ["Technology / IT Security Policy"], "HIGH"),
    ("Monitoring activities", "📊", "Verify system monitoring is active for anomalous behavior.", "Monitoring system alerts, SOC dashboard logs.", ["Technology / IT Security Policy"], "HIGH"),
    ("Clock synchronization", "⏰", "Verify clocks of all relevant systems are synchronized.", "NTP sync status reports, system clocks config.", ["Technology / IT Security Policy"], "LOW"),
    ("Use of privileged utility programs", "⚡", "Verify utility programs that can override controls are restricted.", "Authorized utility list, utility execution logs.", ["Technology / IT Security Policy"], "HIGH"),
    ("Installation of software on operational systems", "📥", "Verify installation of software on production systems is controlled.", "Software installation policy, approved software whitelist.", ["Technology / IT Security Policy"], "MEDIUM"),
    ("Network security", "🌐", "Verify network controls (firewalls, IDS) protect information.", "Network protection configurations (such as firewall rules, segmentation details, or network diagrams).", ["Technology / IT Security Policy"], "HIGH"),
    ("Security of network services", "🌐", "Verify security requirements of network services are identified.", "Network service agreements, secure protocol settings.", ["Technology / IT Security Policy", "Supplier / Third Party Policy"], "MEDIUM"),
    ("Segregation of networks", "🧱", "Verify network groups are segregated based on sensitivity.", "VLAN configurations, network segmentation design.", ["Technology / IT Security Policy"], "HIGH"),
    ("Web filtering", "🌐", "Verify access to external malicious websites is restricted.", "Web filter configs, blocked categories report.", ["Technology / IT Security Policy"], "MEDIUM"),
    ("Use of cryptography", "🔒", "Verify cryptographic controls are designed and implemented.", "Cryptographic configurations (such as encryption policies, SSL/TLS configurations, or key management records).", ["Technology / IT Security Policy"], "HIGH"),
    ("Secure development life cycle", "🏗️", "Verify secure development lifecycle (SDLC) rules are established.", "Secure SDLC guidelines, code review guidelines.", ["Development / Secure Coding Policy"], "HIGH"),
    ("Application security requirements", "🏗️", "Verify application security specs are defined during design.", "Security requirements documents, threat modeling logs.", ["Development / Secure Coding Policy"], "MEDIUM"),
    ("Secure system architecture and engineering principles", "🏛️", "Verify principles for engineering secure systems are followed.", "Architecture design documents, secure engineering guidelines.", ["Development / Secure Coding Policy"], "HIGH"),
    ("Secure coding", "💻", "Verify secure coding practices are applied by developers.", "Secure coding guidelines, SAST scan reports.", ["Development / Secure Coding Policy"], "HIGH"),
    ("Security testing in development and acceptance", "🧪", "Verify security testing is performed during SDLC.", "Penetration testing report, DAST scans.", ["Development / Secure Coding Policy"], "HIGH"),
    ("Outsourced development", "🤝", "Verify outsourced software development is monitored and verified.", "Vendor contracts, code quality reviews for vendor code.", ["Development / Secure Coding Policy", "Supplier / Third Party Policy"], "MEDIUM"),
    ("Separation of development, testing and production environments", "🧱", "Verify dev, test, and production environments are segregated.", "Environment network maps, IAM rules for env separation.", ["Development / Secure Coding Policy", "Technology / IT Security Policy"], "CRITICAL"),
    ("Change management", "🔄", "Verify changes to systems are controlled, authorized, and logged.", "Change management policy, CAB minutes, change tickets.", ["Technology / IT Security Policy", "Development / Secure Coding Policy"], "HIGH"),
    ("Test information", "🧪", "Verify test data is selected, protected, and controlled.", "Test data management policy, data sanitization script logs.", ["Development / Secure Coding Policy"], "MEDIUM"),
    ("Protection of information systems during audit testing", "🛡️", "Verify audit tests affecting production are planned and approved.", "Audit test schedules, change requests for audit activities.", ["Technology / IT Security Policy", "Compliance / Legal Policy"], "LOW")
]

for idx, (name, icon, use_case, expected, scopes, severity) in enumerate(c8_controls, 1):
    sl_num = 59 + idx
    code = f"8.{idx}"
    title_name = to_title_case(name)
    controls.append({
        "sl": sl_num,
        "standard": "ISO 27001",
        "category": "Clause 8 — Technological Controls",
        "label": f"{title_name} ({code})",
        "icon": icon,
        "use_case": f"{code} {title_name}",
        "expected": expected,
        "format": "PDF",
        "prompt_hint": f"Verify compliance against {code} {title_name}. {use_case}",
        "scope_tags": scopes,
        "severity": severity,
        "finding": f"No documented evidence found for {code} ({title_name}).",
        "recommendation": f"Establish, document, and implement procedures to satisfy {code} ({title_name})."
    })

# Write to file
output = {
    "USE_CASES": controls,
    "DEMO_FINDINGS": {},
    "GAP_RESOLUTION": {}
}

# Create matching DEMO_FINDINGS and GAP_RESOLUTION for each control
for c in controls:
    sl_num = c["sl"]
    ctrl_name = c["use_case"]
    output["DEMO_FINDINGS"][str(sl_num)] = [{
        "severity": c["severity"],
        "control": ctrl_name,
        "finding": c["finding"],
        "recommendation": c["recommendation"]
    }]
    
    code = ctrl_name.split(" ")[0]
    words = [code.lower(), c["label"].lower(), c["use_case"].lower()]
    name_words = c["label"].replace("(", "").replace(")", "").lower().split(" ")
    words.extend([w for w in name_words if len(w) > 3])
    output["GAP_RESOLUTION"][ctrl_name] = list(set(words))

# Add the specific CROSS_FILE findings
output["DEMO_FINDINGS"]["CROSS_FILE"] = [
    {"severity":"CRITICAL","control":"Cross-Document Correlation","finding":"Policy PDF (File 1) mandates 90-day password rotation, but Evidence Certificate (File 2) shows rotation set to 180 days.","recommendation":"Sync the actual system settings with the written policy document."},
    {"severity":"HIGH","control":"Cross-Document Correlation","finding":"Incident Plan (File 1) lists an external vendor for forensics, but the vendor contract (File 2) has been expired for 6 months.","recommendation":"Renew the vendor contract or update the Incident Plan with a new forensic partner."}
]

with open("src/core/controls_data.py", "w", encoding="utf-8") as f:
    f.write("# -*- coding: utf-8 -*-\n")
    f.write("USE_CASES = " + repr(output["USE_CASES"]) + "\n\n")
    f.write("DEMO_FINDINGS = " + repr({int(k) if k.isdigit() else k: v for k, v in output["DEMO_FINDINGS"].items()}) + "\n\n")
    f.write("GAP_RESOLUTION = " + repr(output["GAP_RESOLUTION"]) + "\n\n")
    f.write("""
SCOPE_KEYWORDS = {
    "Access Control Policy": ["access control", "rbac", "mfa", "password", "authentication", "privileged access", "identity management", "pam", "vpn", "credentials", "revoke", "grant access", "badge", "keycard", "rfid", "pin", "biometric", "role", "grant", "revoke", "privilege", "admin", "restriction"],
    "Asset Management Policy": ["inventory", "asset list", "acceptable use", "aup", "disposal", "e-waste", "media handling", "sanitization", "laptops", "devices", "return of assets", "register", "owner", "classification", "label", "shred", "transfer", "handover", "return"],
    "Risk Assessment": ["risk assessment", "risk management", "policy", "review", "independent review", "legal requirements", "audit", "compliance", "board oversight", "governance", "threat", "vulnerability", "impact", "likelihood", "matrix", "mitigate", "accept", "residual", "register", "review frequency"],
    "Incident Management Policy": ["incident", "breach", "event reporting", "siem", "logging", "monitoring", "containment", "remediation", "triage", "forensics", "report", "severity", "contain", "escalate", "forensic", "debrief", "gdpr breach", "notify", "lessons", "improve"],
    "Business Continuity Plan": ["continuity", "disaster recovery", "dr plan", "bcp", "disruption", "redundancy", "backup", "restore", "drill", "rto", "rpo", "bia", "failover", "dr site", "test", "crisis", "spokesperson", "recovery"],
    "General Security Policy": ["policy", "annual review", "ciso", "owner", "training", "phishing", "disciplinary", "termination", "acceptable use", "clean desk", "roles", "responsibilities", "segregation", "duties", "awareness", "clear screen"],
    "HR / People Security Policy": ["screening", "background check", "criminal record", "reference check", "verification", "pre-employment", "employment contract", "terms", "conditions", "security responsibilities", "confidentiality", "obligations", "awareness", "phishing", "violation", "sanction", "termination", "offboarding", "post employment", "nda", "non-disclosure", "sign", "remote work", "vpn", "event reporting"],
    "Physical Security Policy": ["perimeter", "fence", "wall", "barrier", "boundary", "secure area", "entry", "access control", "badge", "keycard", "turnstile", "reception", "guard", "visitor", "sign-in", "office", "lock", "restricted area", "server room", "data centre", "cabinet", "cctv", "camera", "surveillance", "monitor", "patrol", "alarm", "detection", "fire", "flood", "power", "environmental", "natural disaster", "clean room", "no photography", "clean desk", "clear screen", "siting", "placement", "off-premises", "laptop", "mobile", "removable", "ups", "generator", "cooling", "hvac", "conduit", "maintenance", "scheduled", "sanitise", "wipe", "destroy", "decommission"],
    "Technology / IT Security Policy": ["endpoint", "laptop", "desktop", "mobile", "device", "mdm", "patch", "antivirus", "encryption", "device policy", "privileged", "admin", "root", "superuser", "elevated", "pam", "review", "need-to-know", "least privilege", "data access", "permission", "acl", "source code", "repository", "git", "version control", "mfa", "password policy", "pin", "biometric", "sso", "authentication", "capacity", "storage", "bandwidth", "antimalware", "edr", "cve", "scan", "vulnerability", "baseline", "hardening", "cmdb", "delete", "erase", "purge", "masking", "anonymise", "dlp", "leakage", "exfiltration", "backup", "restore", "failover", "ha", "redundancy", "log", "audit log", "siem", "alert", "soc", "anomaly", "ntp", "time sync", "utility", "software install", "whitelist", "network", "firewall", "segmentation", "vlan", "dmz", "web filter", "cryptography", "tls", "ssl", "aes", "sdlc", "secure coding", "code review", "sast", "audit access", "read-only"],
    "Supplier / Third Party Policy": ["supplier", "vendor", "third party", "contractor", "outsource", "security requirements", "agreement", "assessment", "contract", "sla", "nda", "security clause", "terms", "obligations", "supply chain", "ict", "provenance", "integrity", "supplier review", "audit", "performance", "monitor", "service level", "cloud", "saas", "paas", "iaas", "CSP"],
    "Development / Secure Coding Policy": ["sdlc", "secure development", "devsecops", "security requirements", "design review", "application security", "owasp", "input validation", "authentication", "authorisation", "architecture", "secure design", "defence in depth", "engineering principle", "secure coding", "code review", "sast", "coding standard", "vulnerability", "penetration test", "dast", "uat", "acceptance testing", "outsourced development", "third party dev", "dev", "test", "production", "environment separation", "prod access", "pipeline", "change management", "change control", "cab", "approval", "test data", "production data", "sanitise", "mask", "anonymise"],
    "Compliance / Legal Policy": ["legal", "regulatory", "statutory", "compliance", "law", "regulation", "requirement", "jurisdiction", "gdpr", "dpdp", "intellectual property", "ip", "copyright", "license", "patent", "records", "retention", "storage", "archive", "protect", "destroy", "privacy", "pii", "personal data", "data subject", "consent", "audit", "assessment"]
}
""")

print("Controls dataset created successfully!")
