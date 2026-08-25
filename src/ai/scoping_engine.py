import json
import requests
import re
import time
from src.core.controls_data import USE_CASES


def _load_custom_controls_from_db():
    """
    Load auditor-defined custom controls from the database at runtime.
    Returns:
        extra_doc_type_mappings  : dict {category -> [control_name, ...]}
        extra_content_signals    : dict {category -> [keyword, ...]}
        extra_scope_descriptions : dict {category -> description_str}
    Silently returns empty dicts if the DB is not yet initialised.
    """
    extra_mappings      = {}
    extra_signals       = {}
    extra_descriptions  = {}
    try:
        from src.db.database import get_all_custom_controls
        rows = get_all_custom_controls(active_only=True)
        for row in rows:
            cat  = row["category"]
            name = row["control_name"]
            kws  = row["keywords"]          # list[str]
            desc = row["description"] or name

            # Option 1: merge control into DOC_TYPE_MAPPINGS equivalent
            extra_mappings.setdefault(cat, [])
            if name not in extra_mappings[cat]:
                extra_mappings[cat].append(name)

            # Option 1 + 2: add keywords to CONTENT_SIGNALS equivalent
            if kws:
                extra_signals.setdefault(cat, [])
                extra_signals[cat].extend(kws)

            # Option 3: add description to SCOPE_DESCRIPTIONS equivalent
            # Append to existing description so semantic similarity covers it
            if cat in extra_descriptions:
                extra_descriptions[cat] += ", " + desc
            else:
                extra_descriptions[cat] = desc
    except Exception as db_err:
        print(f"[SCOPING ENGINE] Custom controls DB load skipped: {db_err}")
    return extra_mappings, extra_signals, extra_descriptions

# ── DOC TYPE → ISO 27001:2022 CONTROL MAPPINGS ───────────────────────────────
DOC_TYPE_MAPPINGS = {
    "Access Control Policy": [
        "5.15 Access Control", "5.16 Identity Management",
        "5.17 Authentication Information", "5.18 Access Rights",
        "8.2 Privileged Access Rights", "8.3 Information Access Restriction",
        "8.5 Secure Authentication"
    ],
    "Asset Management Policy": [
        "5.9 Inventory of Information and Other Associated Assets",
        "5.10 Acceptable Use of Information and Other Associated Assets",
        "5.11 Return of Assets", "5.12 Classification of Information",
        "5.13 Labelling of Information", "5.14 Information Transfer"
    ],
    "Risk Assessment": [
        "5.1 Policies for Information Security",
        "5.2 Information Security Roles and Responsibilities",
        "5.3 Segregation of Duties", "5.4 Management Responsibilities",
        "5.5 Contact with Authorities", "5.6 Contact with Special Interest Groups",
        "5.7 Threat Intelligence", "5.8 Information Security in Project Management",
        "5.35 Independent Review of Information Security",
        "5.36 Compliance with Policies and Standards for Information Security",
        "5.37 Documented Operating Procedures"
    ],
    "Incident Management Policy": [
        "5.24 Information Security Incident Management Planning and Preparation",
        "5.25 Assessment and Decision on Information Security Events",
        "5.26 Response to Information Security Incidents",
        "5.27 Learning from Information Security Incidents",
        "5.28 Collection of Evidence"
    ],
    "Business Continuity Plan": [
        "5.29 Information Security During Disruption",
        "5.30 Ict Readiness for Business Continuity",
        "8.13 Information Backup",
        "8.14 Redundancy of Information Processing Facilities"
    ],
    "General Security Policy": [
        "5.1 Policies for Information Security",
        "5.2 Information Security Roles and Responsibilities",
        "5.3 Segregation of Duties", "5.4 Management Responsibilities",
        "5.5 Contact with Authorities", "5.6 Contact with Special Interest Groups",
        "5.7 Threat Intelligence", "5.8 Information Security in Project Management",
        "5.35 Independent Review of Information Security",
        "5.36 Compliance with Policies and Standards for Information Security",
        "5.37 Documented Operating Procedures"
    ],
    "HR / People Security Policy": [
        "6.1 Screening", "6.2 Terms and Conditions of Employment",
        "6.3 Information Security Awareness, Education and Training",
        "6.4 Disciplinary Process",
        "6.5 Responsibilities after Termination or Change of Employment",
        "6.6 Confidentiality or Non-disclosure Agreements",
        "6.7 Remote Working", "6.8 Information Security Event Reporting"
    ],
    "Physical Security Policy": [
        "5.15 Access Control",
        "7.1 Physical Security Perimeters", "7.2 Physical Entry",
        "7.3 Securing Offices, Rooms and Facilities", "7.4 Physical Security Monitoring",
        "7.5 Protecting against Physical and Environmental Threats",
        "7.6 Working in Secure Areas", "7.7 Clear Desk and Clear Screen",
        "7.8 Equipment Siting and Protection", "7.9 Security of Assets Off-premises",
        "7.10 Storage Media", "7.11 Supporting Utilities", "7.12 Cabling Security",
        "7.13 Equipment Maintenance", "7.14 Secure Disposal or Re-use of Equipment"
    ],
    "Technology / IT Security Policy": [
        "8.1 User Endpoint Devices", "8.2 Privileged Access Rights",
        "8.3 Information Access Restriction", "8.4 Access to Source Code",
        "8.5 Secure Authentication", "8.6 Capacity Management",
        "8.7 Protection against Malware", "8.8 Management of Technical Vulnerabilities",
        "8.9 Configuration Management", "8.10 Information Deletion", "8.11 Data Masking",
        "8.12 Data Leakage Prevention", "8.13 Information Backup",
        "8.14 Redundancy of Information Processing Facilities", "8.15 Logging",
        "8.16 Monitoring Activities", "8.17 Clock Synchronization",
        "8.18 Use of Privileged Utility Programs",
        "8.19 Installation of Software on Operational Systems",
        "8.20 Network Security", "8.21 Security of Network Services",
        "8.22 Segregation of Networks", "8.23 Web Filtering",
        "8.24 Use of Cryptography", "8.25 Secure Development Life Cycle",
        "8.26 Application Security Requirements",
        "8.27 Secure System Architecture and Engineering Principles",
        "8.28 Secure Coding", "8.29 Security Testing in Development and Acceptance",
        "8.30 Outsourced Development",
        "8.31 Separation of Development, Testing and Production Environments",
        "8.32 Change Management", "8.33 Test Information",
        "8.34 Protection of Information Systems during Audit Testing"
    ],
    "Supplier / Third Party Policy": [
        "5.19 Information Security in Supplier Relationships",
        "5.20 Addressing Information Security Within Supplier Agreements",
        "5.21 Managing Information Security in The Ict Supply Chain",
        "5.22 Monitoring, Review and Change Management of Supplier Services",
        "5.23 Information Security for Use of Cloud Services"
    ],
    "Development / Secure Coding Policy": [
        "8.25 Secure Development Life Cycle", "8.26 Application Security Requirements",
        "8.27 Secure System Architecture and Engineering Principles", "8.28 Secure Coding",
        "8.29 Security Testing in Development and Acceptance", "8.30 Outsourced Development",
        "8.31 Separation of Development, Testing and Production Environments",
        "8.32 Change Management", "8.33 Test Information",
        "8.34 Protection of Information Systems during Audit Testing"
    ],
    "Compliance / Legal Policy": [
        "5.31 Legal, Statutory, Regulatory and Contractual Requirements",
        "5.32 Intellectual Property Rights", "5.33 Protection of Records",
        "5.34 Privacy and Protection of Personally Identifiable Information (Pii)",
        "5.36 Compliance with Policies and Standards for Information Security"
    ]
}

# ── CONTENT-BASED KEYWORD SIGNALS → Doc Types ────────────────────────────────
# If these keywords appear in document content, always add the corresponding type
CONTENT_SIGNALS = {
    "HR / People Security Policy": [
        "screening", "pre-employment", "onboarding", "termination of employment",
        "awareness training", "disciplinary", "confidentiality agreement", "remote working",
        "nda", "non-disclosure", "background check", "joiner", "leaver",
        # New: 6.2–6.8 sub-control keywords
        "employment terms", "terms and conditions", "employment contract", "offer letter",
        "security awareness", "phishing awareness", "staff training", "e-learning",
        "misconduct", "policy violation", "disciplinary action",
        "offboarding", "exit process", "resignation", "dismissal", "account deactivation",
        "non disclosure", "confidentiality clause", "work from home", "wfh", "telework",
        "home working", "vpn policy", "event reporting", "how to report security"
    ],
    "Physical Security Policy": [
        "badge", "physical access", "secure area", "clean desk", "visitor",
        "cctv", "tailgating", "piggyback", "reception", "keycard", "facility access",
        "physical security", "equipment disposal", "secure room",
        # New: 7.2–7.14 sub-control keywords
        "physical entry", "entry control", "door access", "turnstile", "entry point",
        "secure office", "secure facility", "server room", "data center access",
        "camera surveillance", "security camera", "video surveillance",
        "environmental threat", "flood", "fire protection", "power protection", "ups",
        "working in secure area", "restricted area policy", "secure zone",
        "clear screen", "unattended workstation", "equipment siting", "rack security",
        "assets off-premises", "remote equipment", "equipment offsite",
        "storage media", "removable media", "usb", "media handling", "removable storage",
        "supporting utilities", "power supply", "generator", "utility failure",
        "cabling", "cable security", "network cabling", "structured cabling",
        "equipment maintenance", "maintenance schedule", "hardware maintenance",
        "secure disposal", "data destruction", "disk wipe", "degauss", "decommission"
    ],
    "Incident Management Policy": [
        "incident response", "security incident", "breach notification", "containment",
        "eradication", "forensic", "evidence collection", "incident severity",
        "soc ", "security operations",
        # New: 5.25–5.28 sub-control keywords
        "incident assessment", "incident triage", "event decision", "incident classification",
        "incident handling", "recovery response",
        "lessons learned", "post incident review", "incident review", "learning from incidents",
        "incident debrief", "digital forensic", "chain of custody"
    ],
    "Access Control Policy": [
        "logical access", "user account", "privilege", "authentication", "password",
        "identity management", "access rights", "role-based", "rbac", "mfa",
        "multi-factor", "single sign", "sso", "least privilege", "user credential",
        "system account", "login credential",
        # New: 5.16–5.18, 8.2–8.3 sub-control keywords
        "user provisioning", "joiner leaver", "account lifecycle", "iam policy", "user lifecycle",
        "permission management", "access provisioning", "least privilege access",
        "privileged access", "pam", "pim", "admin access", "root access",
        "information access restriction", "need to know", "access restriction"
    ],
    "Technology / IT Security Policy": [
        "endpoint", "antivirus", "malware", "firewall", "encryption", "patch",
        "vulnerability", "network security", "logging", "monitoring", "backup",
        "cryptography", "configuration management", "data loss prevention",
        # New: 8.1, 8.4, 8.7, 8.9–8.23 sub-control keywords
        "user endpoint", "laptop policy", "mobile device", "mdm", "byod", "endpoint security",
        "source code", "code repository", "git access", "github", "gitlab",
        "anti-malware", "edr", "malware protection", "av policy",
        "baseline configuration", "hardening", "cmdb", "config baseline", "secure configuration",
        "data deletion", "information deletion", "secure erase", "data wiping", "right to erasure",
        "data masking", "anonymization", "pseudonymization", "masking policy",
        "dlp", "data leakage prevention", "data exfiltration", "information leakage",
        "redundancy", "failover", "high availability", "active active", "active passive",
        "log management", "syslog", "audit logs", "event logs", "logging policy", "log retention",
        "clock synchronization", "ntp", "time server", "time sync",
        "privileged utility", "admin tools", "utility programs", "system utilities",
        "software installation", "approved software", "application whitelist", "install policy",
        "network services", "api gateway", "managed network service",
        "vlan", "network segmentation", "dmz", "network zone", "micro segmentation",
        "web filtering", "url filtering", "proxy", "content filter", "internet filtering"
    ],
    "Supplier / Third Party Policy": [
        "supplier", "vendor", "third party", "outsourc", "service provider",
        "cloud service", "supply chain", "contractor agreement", "sla",
        # New: 5.19–5.23 sub-control keywords
        "supplier relationship", "vendor relationship", "supplier policy",
        "supplier agreement", "vendor contract", "third party contract", "service contract",
        "ict supply chain", "supply chain security", "hardware supply", "software supply",
        "supply chain risk", "supplier monitoring", "vendor monitoring", "third party review",
        "supplier audit", "vendor performance",
        "saas", "iaas", "paas", "cloud provider", "aws", "azure", "gcp", "cloud security"
    ],
    "Risk Assessment": [
        "risk register", "risk assessment", "threat", "vulnerability assessment",
        "risk treatment", "residual risk", "risk owner", "risk appetite",
        # New: 5.7, 5.8 sub-control keywords
        "threat intelligence", "threat feed", "cti", "threat data", "ioc",
        "indicators of compromise", "project security", "sdlc governance", "project risk"
    ],
    "Business Continuity Plan": [
        "business continuity", "disaster recovery", "bcp", "drp", "rto", "rpo",
        "recovery time", "recovery point", "resilience", "failover",
        # New: 5.30, 8.13, 8.14 sub-control keywords
        "ict continuity", "ict readiness", "it continuity", "system continuity",
        "technology continuity", "redundancy", "high availability", "restore"
    ],
    "Compliance / Legal Policy": [
        "gdpr", "pii", "personal data", "data privacy", "legal requirement",
        "regulatory", "intellectual property", "data protection", "privacy",
        # New: 5.31–5.36 sub-control keywords
        "statutory requirement", "contractual requirement", "compliance obligation",
        "copyright", "ip rights", "software license", "license management", "ipr",
        "records retention", "record management", "log retention policy",
        "independent review", "internal audit", "isms review", "external audit",
        "compliance check", "policy compliance", "compliance review", "standards compliance"
    ],
    "General Security Policy": [
        "information security policy", "iprotect", "information protection policy",
        "security policy", "isms", "iso 27001",
        # New: 5.1–5.8, 5.35–5.37 sub-control keywords
        "roles and responsibilities", "isms roles", "security roles",
        "segregation of duties", "separation of duties", "sod", "dual control",
        "management commitment", "management responsibilities", "senior management",
        "contact with authorities", "law enforcement", "regulatory body",
        "special interest group", "isac", "industry group", "security forum",
        "project management", "security in projects",
        "operating procedures", "sop", "documented procedures",
        "standard operating procedure", "work instructions"
    ],
    "Asset Management Policy": [
        "asset inventory", "asset register", "asset classification", "asset owner",
        "information asset", "data classification", "asset management",
        # New: 5.10–5.14 sub-control keywords
        "acceptable use", "aup", "usage policy", "acceptable use policy", "permitted use",
        "return of assets", "asset return", "exit assets", "equipment return",
        "information classification", "classification scheme", "sensitivity label",
        "data labelling", "information labelling", "marking", "classification marking",
        "information transfer", "data transfer", "file transfer", "email security",
        "secure transfer", "ftp", "sftp"
    ],
    "Development / Secure Coding Policy": [
        "secure coding", "sdlc", "development lifecycle", "code review",
        "penetration test", "security testing", "devops", "ci/cd",
        # New: 8.25–8.34 sub-control keywords
        "secure development", "secure development lifecycle", "secure development policy",
        "application security", "app security requirements", "security requirements",
        "security in design", "secure architecture", "security architecture",
        "engineering principles", "security by design", "architecture review",
        "coding standard", "owasp", "sast", "dast", "static analysis",
        "acceptance testing", "uat security", "pre-production testing",
        "outsourced development", "third party development", "vendor development",
        "separation of environments", "dev test prod", "environment separation",
        "non-production", "staging environment",
        "change management", "change control", "change request", "change advisory board",
        "cab", "change approval",
        "test information", "test data", "test data management", "production data in test",
        "sanitised test data", "audit testing", "audit tools", "audit environment"
    ]
}

# ── UMBRELLA POLICY DETECTION ─────────────────────────────────────────────────
# These doc types should ALWAYS trigger multi-clause expansion
UMBRELLA_POLICY_KEYWORDS = [
    "information protection policy", "iprotect", "information security policy",
    "security policy", "master security", "isms policy"
]

UMBRELLA_EXPANDS_TO = [
    "General Security Policy",
    "Access Control Policy",
    "HR / People Security Policy",
    "Physical Security Policy",
    "Technology / IT Security Policy",
    "Incident Management Policy",
    "Supplier / Third Party Policy",
    "Risk Assessment",
    "Compliance / Legal Policy"
]


def _apply_content_signals(context_lower: str, doc_types: list,
                           extra_signals: dict = None) -> list:
    """
    Scan document content for keyword signals and add missing doc types.
    Enforces word boundaries for short abbreviations (<= 4 chars) to prevent substring false matches.
    Also scans extra_signals from auditor-defined custom controls (Option 1 + 2).
    """
    doc_types_set = set(doc_types)

    # Build merged signal dict: hardcoded + custom
    merged_signals = dict(CONTENT_SIGNALS)
    if extra_signals:
        for cat, kws in extra_signals.items():
            merged_signals.setdefault(cat, [])
            merged_signals[cat] = list(set(merged_signals[cat] + kws))

    for dtype, keywords in merged_signals.items():
        for kw in keywords:
            # Enforce word boundaries for abbreviations or short terms
            if len(kw) <= 4 or kw in ["bcp", "drp", "rto", "rpo", "nda", "mfa", "sso", "rbac", "soc"]:
                pattern = r"\b" + re.escape(kw) + r"\b"
                if re.search(pattern, context_lower):
                    doc_types_set.add(dtype)
                    break
            else:
                if kw in context_lower:
                    doc_types_set.add(dtype)
                    break
    return list(doc_types_set)


def _check_umbrella_policy(context_lower: str, doc_types: list) -> list:
    """
    If document looks like a master/umbrella policy, expand to all relevant types.
    Fixes the iProtect false-narrow-scoping problem.
    """
    is_umbrella = any(kw in context_lower[:5000] for kw in UMBRELLA_POLICY_KEYWORDS)
    if is_umbrella:
        doc_types_set = set(doc_types)
        for dt in UMBRELLA_EXPANDS_TO:
            doc_types_set.add(dt)
        return list(doc_types_set)
    return doc_types


def _get_candidate_controls(doc_types, extra_mappings: dict = None):
    """Retrieve candidate control names based on identified document types.
    Merges hardcoded ISO 27001:2022 controls with auditor-defined custom controls.
    """
    # Build merged mapping: hardcoded + custom (Option 1)
    merged = dict(DOC_TYPE_MAPPINGS)
    if extra_mappings:
        for cat, ctrls in extra_mappings.items():
            merged.setdefault(cat, [])
            for c in ctrls:
                if c not in merged[cat]:
                    merged[cat].append(c)

    candidates = set()
    for dt in doc_types:
        for c in merged.get(dt, []):
            candidates.add(c)

    if not candidates:
        for dt, controls in merged.items():
            for c in controls:
                candidates.add(c)

    return list(candidates)


SCOPE_DESCRIPTIONS = {
    "Access Control Policy": "Logical user access control, login accounts, password policy, multi-factor authentication MFA, single sign-on SSO, role-based access RBAC, privileged accounts",
    "Asset Management Policy": "Inventory of assets, acceptable use policy AUP, classification of information, data labelling, media disposal, device return, asset lifecycle",
    "Risk Assessment": "Information security risk assessment, threat identification, vulnerability management, risk treatment plans, management oversight",
    "Incident Management Policy": "Information security incident management, security events, reporting incident tickets, breach containment, logs, forensic evidence, lessons learned",
    "Business Continuity Plan": "Business continuity plans, disaster recovery plans, ICT readiness, backup restoration testing, systems redundancy, disruptions",
    "General Security Policy": "High level information security policy, ISMS framework, roles and responsibilities, management commitment",
    "HR / People Security Policy": "Background screening, employment terms and conditions, nda confidentiality agreements, awareness training, disciplinary actions, offboarding termination",
    "Physical Security Policy": "Physical security perimeters, physical entry control, visitor logs, secure offices, camera monitoring, environmental threats, clean desk clear screen",
    "Technology / IT Security Policy": "Technical IT security, endpoint protection, antivirus malware, firewalls, logs, network segmentation, web filtering, patch management, cryptography encryption",
    "Supplier / Third Party Policy": "Vendor relationships, supplier contracts, supply chain security, monitoring supplier services, cloud services security",
    "Development / Secure Coding Policy": "Secure development lifecycle SDLC, secure coding standards, security testing, source code protection, separate dev test prod environments",
    "Compliance / Legal Policy": "Legal statutory regulatory compliance, intellectual property protection, records retention policy, PII privacy protection, audits"
}

_category_embeddings_cache = {}


def cosine_similarity(v1, v2):
    """Calculates cosine similarity between two vectors."""
    if not v1 or not v2:
        return 0.0
    dot = sum(a * b for a, b in zip(v1, v2))
    norm_a = sum(a * a for a in v1) ** 0.5
    norm_b = sum(b * b for b in v2) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def detect_scope_and_controls(context, llm_model=None):
    """
    Zero-LLM deterministic + semantic scope detection.
    Combines:
      - Option 1: Auditor-provided keyword signals (from DB custom_controls)
      - Option 2: Auto-generated keywords (stored in DB by keyword_generator)
      - Option 3: Nomic semantic similarity fallback for controls with no keywords
    """
    start_time = time.time()
    print(f"\n[{time.strftime('%H:%M:%S')}] [INFO] Starting Dual-Layer Scope Detection (Option A + Custom Controls)...")

    # ── PRE-LOAD: Auditor-defined custom controls from DB ─────────────────────
    extra_mappings, extra_signals, extra_descriptions = _load_custom_controls_from_db()
    if extra_mappings:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Loaded {sum(len(v) for v in extra_mappings.values())} custom controls from DB")

    context_lower = context.lower()
    doc_types_set = set()
    ollama_offline = False

    # ── LAYER 1: Python Keyword Signals (Instant) — Option 1 + 2 ─────────────
    # Merges hardcoded CONTENT_SIGNALS with auditor-defined keywords from DB
    doc_types_list = _apply_content_signals(context_lower, [], extra_signals)
    for dt in doc_types_list:
        doc_types_set.add(dt)

    # ── LAYER 2: Semantic Embedding Match (~50ms) — Option 3 Fallback ────────
    # Merges SCOPE_DESCRIPTIONS with custom control descriptions from DB
    merged_descriptions = dict(SCOPE_DESCRIPTIONS)
    for cat, desc in extra_descriptions.items():
        if cat in merged_descriptions:
            merged_descriptions[cat] += ", " + desc
        else:
            merged_descriptions[cat] = desc

    doc_snippet = context[:800].strip()
    if doc_snippet:
        try:
            from src.core.llm_client import get_embedding
            from src.core.retrieval import _cosine_similarity

            # Warm up category embeddings cache (includes custom control descriptions)
            for cat, desc in merged_descriptions.items():
                if cat not in _category_embeddings_cache:
                    _category_embeddings_cache[cat] = get_embedding(desc)

            # Get document vector
            doc_vector = get_embedding(doc_snippet)

            # Calculate cosine similarity — catches controls with no keyword match
            if doc_vector:
                print(f"[{time.strftime('%H:%M:%S')}] [INFO] Computing semantic scope matches (incl. custom controls)...")
                for cat, cat_vector in _category_embeddings_cache.items():
                    if cat_vector:
                        sim = _cosine_similarity(doc_vector, cat_vector)
                        if sim >= 0.645:
                            print(f"   * Semantic Match: {cat} (Similarity: {sim:.3f})")
                            doc_types_set.add(cat)
        except Exception as embed_err:
            print(f"[{time.strftime('%H:%M:%S')}] [WARNING] Semantic scoping failed: {embed_err}")

    doc_types = list(doc_types_set)

    # ── LAYER 3: Umbrella Policy Expansion ────────────────────────────────────
    before_umbrella = set(doc_types)
    doc_types = _check_umbrella_policy(context_lower, doc_types)
    added_by_umbrella = set(doc_types) - before_umbrella
    if added_by_umbrella:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Umbrella expansion added: {list(added_by_umbrella)}")

    # ── LAYER 4: Map doc types to controls (hardcoded + custom) ──────────────
    selected_controls = _get_candidate_controls(doc_types, extra_mappings)

    # ── LAYER 5: Fallback if empty ────────────────────────────────────────────
    if not doc_types:
        doc_types = list(DOC_TYPE_MAPPINGS.keys()) + list(extra_mappings.keys())
        selected_controls = _get_candidate_controls(doc_types, extra_mappings)
        print(f"[{time.strftime('%H:%M:%S')}] [WARN] No scopes detected — falling back to ALL scopes")

    elapsed = time.time() - start_time
    print(f"[{time.strftime('%H:%M:%S')}] [SUCCESS] Scope Detection completed in {elapsed:.4f}s")
    print(f"   Final Doc Types ({len(doc_types)}): {doc_types}")

    return selected_controls, None, doc_types, ollama_offline
