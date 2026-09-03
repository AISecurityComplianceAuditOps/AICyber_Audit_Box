# PQC Integration & Data Extraction Manual

This document is the definitive guide on how the AI Cyber Audit Box connects to external environments (via MCP Servers), parses user requests, and surgically extracts Post-Quantum Cryptography (PQC) and security evidence.

---

## 1. Setting Up the MCP Servers
The application uses the Model Context Protocol (MCP) to securely tunnel into your infrastructure. You can add servers via the UI's **+ Add New** button in the Import Modal.

### GitHub
- **Type:** `github`
- **Credentials Required:** Personal Access Token (PAT).
- **Purpose:** Extracts source code, IaC, and CI/CD pipelines.

### Jira
- **Type:** `jira`
- **Credentials Required:** Jira Account Email, Base URL (e.g., `https://domain.atlassian.net`), and API Token.
- **Purpose:** Extracts security tickets, risk assessments, and compliance documentation.

### PostgreSQL (Local/Remote)
- **Type:** `postgres`
- **Credentials Required:** Full Database Connection URL (e.g., `postgresql://user:pass@host:port/db`).
- **Purpose:** Extracts live database configurations, TLS ciphers, and authentication rules.

### Azure Cloud
- **Type:** `azure`
- **Credentials Required:** Tenant ID, Client ID, Client Secret, and Subscription ID.
- **Prerequisite:** You must create an App Registration (Service Principal) in Azure Entra ID and grant it the `Reader` and `Key Vault Reader` roles at the Subscription level.
- **Purpose:** Extracts live infrastructure configuration and Key Vault cryptography.

---

## 2. Request Parsing & Modes
When you trigger an import from the UI, the backend (`mcp.py`) dynamically routes the request based on the selected server and the **Import Mode**.

- **General Mode:** A targeted import. For GitHub, it extracts exactly the file or folder you specify. For Jira, it pulls a specific Issue Key. For Azure, it runs basic Resource Health scans.
- **PQC Mode:** An automated, high-level security sweep. The AI ignores your file paths (for databases/cloud) and instead executes a predefined matrix of security queries to map your entire cryptographic and architectural attack surface.

---

## 3. The Extraction Matrix (PQC Mode)

When running a **PQC Scan**, the backend extracts specific security assets at different levels depending on the server type.

### Level 1: GitHub (Source Code & Infrastructure-as-Code)
GitHub repositories contain massive amounts of noise (e.g., `node_modules`, UI assets). The backend uses a 3-layer filter to extract 100% of the cryptographic evidence while ignoring 100% of the noise:

1. **Exact Match Targets:** Unconditionally extracts critical configurations like `nginx.conf`, `web.config`, `id_rsa`, `pom.xml`, and `dockerfile`.
2. **Targeted Extensions:** Unconditionally extracts security files ending in `.pem`, `.crt`, `.key`, `.p12`, `.tf`, `.bicep`, and `.env`.
3. **Keyword-Gated Extensions:** For generic files (`.json`, `.yaml`, `.conf`), the file is ONLY extracted if its name contains a security keyword like `crypto`, `tls`, `vault`, `kyber`, `saml`, or `secret` (e.g., `database.yaml` is ignored, but `database-tls.yaml` is extracted).

> [!TIP]
> **Fallback Mechanism:** If GitHub blocks the raw download URL, the system automatically routes the request through the official GitHub API to ensure the file is retrieved.

### Level 2: PostgreSQL (Live Database Security)
For databases, files don't apply. Instead, the backend automatically runs a suite of SQL commands to extract:

1. **TLS/SSL Primitives:** `SHOW ssl;` and `SHOW ssl_ciphers;`
2. **Active Encrypted Connections:** Joins `pg_stat_ssl` and `pg_stat_activity` to prove encryption-in-transit.
3. **Client Authentication Rules:** Extracts `pg_hba_file_rules` to detect dangerous trust-based authentications and IP spoofing vulnerabilities.
4. **Password Standards:** Extracts `password_encryption` settings to ensure databases aren't using legacy hashing (e.g. `md5`).
5. **Privilege Matrix:** Queries `pg_roles` to map out superusers, roles with create-db powers, and login permissions.
6. **Audit Logging:** Extracts `log_statement` and `log_connections` configs.

### Level 3: Azure Cloud (Live Infrastructure & HSMs)
For Azure, the backend queries the `@azure/mcp` API to map the broader network and Key Vaults:

1. **Key Vault Cryptography:** If a Vault Name is provided in the UI, it extracts the raw RSA sizes and ECC curves for all keys and certificates.
2. **SQL Server Enclaves:** Scans all SQL servers for network firewall rules and Entra ID (Azure AD) admin enforcements.
3. **Storage Encryption:** Scans all Storage Accounts to verify `supportsHttpsTrafficOnly` is true and `minimumTlsVersion` is strictly TLS 1.2+.
4. **RBAC:** Extracts subscription-level Role Assignments to identify overly permissive access.
