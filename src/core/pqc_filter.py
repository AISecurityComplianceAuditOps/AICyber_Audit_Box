import os

EXACT_MATCH_FILES = {
    "httpd.conf", "ssl.conf", "haproxy.cfg", "web.config",
    "my.cnf", "sql.config", "postgresql.conf", "sqlnet.ora",
    "sshd_config", "id_rsa", "id_ed25519", "ipsec.conf", "wg0.conf",
    "pom.xml", "build.gradle", "requirements.txt", "pyproject.toml", "package.json",
    "dockerfile", "ntds.dit"
}

PQC_EXTENSIONS = {
    ".pem", ".crt", ".cer", ".der", ".p12", ".pfx", ".key", ".pkcs8", ".jks", 
    ".ovpn", ".tf", ".bicep", ".env"
}

GENERIC_EXTENSIONS = {
    ".conf", ".cfg", ".txt", ".xml", ".json", ".yaml", ".yml", ".ini", ".toml", ".cpg"
}

PQC_KEYWORDS = {
    "crypto", "cert", "tls", "ssl", "key", "rsa", "ecc", "kyber", 
    "dilithium", "falcon", "sphincs", "security", "vault", "kms", 
    "saml", "oauth", "oidc", "kerberos", "luks", "secret", "pqc"
}

def is_pqc_file(filename: str) -> bool:
    filename_lower = filename.lower()
    basename = os.path.basename(filename_lower)
    
    # 1. Exact filenames
    if basename in EXACT_MATCH_FILES:
        return True
        
    ext = os.path.splitext(basename)[1]
    
    # 2. Targeted unconditional extensions
    if ext in PQC_EXTENSIONS:
        return True
        
    # 3. Generic extensions (MUST contain a security keyword)
    if ext in GENERIC_EXTENSIONS or ext == "":
        for kw in PQC_KEYWORDS:
            if kw in basename:
                return True
                
    return False
