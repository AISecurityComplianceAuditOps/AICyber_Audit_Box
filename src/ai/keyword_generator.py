from __future__ import annotations
import re

_STOP_WORDS = {
    "of","the","and","or","for","to","in","on","at","by","an","a",
    "with","from","is","are","be","been","was","were","has","have",
    "that","this","it","its","as","if","all","any","not","no",
    "use","used","using","based","related","associated","applicable",
    "information","security","management","policy","procedures","process",
    "system","systems","within","during","after","before","between",
    "into","through","other","each","such","how","when","where","which","their",
}

_SYNONYM_MAP = {
    "access":["access control","access rights","access management"],
    "authentication":["mfa","multi-factor","password","login","credential"],
    "cryptography":["encryption","aes","tls","ssl","key management"],
    "encryption":["cryptography","aes","tls","ssl","cipher"],
    "backup":["recovery","restore","snapshot","archive"],
    "continuity":["bcp","disaster recovery","drp","resilience","failover"],
    "disaster":["drp","recovery","failover","bcp"],
    "recovery":["rto","rpo","restore","failover","bcp"],
    "vulnerability":["cve","patch","exploit","weakness","scan"],
    "patch":["update","hotfix","vulnerability","cve"],
    "network":["firewall","vlan","subnet","segmentation","dmz"],
    "logging":["audit log","siem","event log","monitoring"],
    "monitoring":["logging","siem","alert","detection"],
    "incident":["breach","event","response","containment","forensic"],
    "supplier":["vendor","third party","outsourc","contractor","service provider"],
    "vendor":["supplier","third party","outsourc","sla"],
    "cloud":["saas","iaas","paas","azure","aws","gcp"],
    "physical":["badge","cctv","facility","clean desk","visitor"],
    "screening":["background check","pre-employment","onboarding"],
    "training":["awareness","education","e-learning"],
    "awareness":["training","education","phishing simulation"],
    "privacy":["gdpr","pii","personal data","data protection"],
    "gdpr":["privacy","pii","personal data","data subject"],
    "risk":["risk assessment","risk register","threat","risk treatment"],
    "malware":["antivirus","ransomware","endpoint protection","edr"],
    "endpoint":["laptop","desktop","mobile device","mdm"],
    "change":["change management","change control","release"],
    "coding":["sdlc","secure development","code review","devops"],
    "development":["sdlc","secure coding","ci/cd","devops"],
    "identity":["iam","idm","provisioning","deprovisioning"],
    "privilege":["admin","superuser","least privilege","pam"],
    "data":["data classification","data loss","dlp","data masking"],
    "classification":["labelling","data classification","sensitivity label"],
    "asset":["asset inventory","asset register","cmdb"],
    "disposal":["sanitisation","degauss","secure wipe","destruction"],
    "segregation":["separation of duties","sod","dual control"],
    "compliance":["regulatory","audit","legal requirement","gdpr"],
    "pii":["personal data","gdpr","privacy","data subject"],
    "ai":["artificial intelligence","machine learning","ml model","llm"],
    "machine":["ai","artificial intelligence","ml","model"],
    "quantum":["post-quantum","quantum cryptography","pqc"],
    "zero":["zero trust","ztna","microsegmentation"],
}


def generate_keywords(control_name, description=""):
    """Auto-generate keyword signals from a control name + optional description."""
    combined = (control_name + " " + description).lower()
    combined = re.sub(r"^\d+\.\d+\s*", "", combined)
    tokens = re.split(r"[\s\-/_,:;]+", combined)
    meaningful = [t for t in tokens if t and t not in _STOP_WORDS and len(t) > 2]
    keywords = set(meaningful)
    words = combined.split()
    for i in range(len(words) - 1):
        if words[i] not in _STOP_WORDS and words[i+1] not in _STOP_WORDS:
            keywords.add(words[i] + " " + words[i+1])
    expansion = set()
    for kw in list(keywords):
        for seed, synonyms in _SYNONYM_MAP.items():
            if seed in kw:
                expansion.update(synonyms)
    keywords.update(expansion)
    keywords = {k for k in keywords if k.strip() and k not in _STOP_WORDS}
    return sorted(keywords)
