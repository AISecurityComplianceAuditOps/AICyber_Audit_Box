import sys
import os
import subprocess
import ipaddress
import datetime

def generate_ssl_cert(cert_path="cert.pem", key_path="key.pem", domains=None):
    """Generates trusted SSL certificate using mkcert or cryptography fallback."""
    if domains is None:
        domains = [
            "localhost",
            "127.0.0.1",
            "::1"
        ]

    abs_cert = os.path.abspath(cert_path)
    abs_key = os.path.abspath(key_path)

    # Check if mkcert.exe is available for 100% trusted green lock SSL
    mkcert_bin = os.path.join(os.path.dirname(abs_cert), "mkcert.exe")
    if os.path.exists(mkcert_bin):
        print(f"[SSL] Generating Trusted SSL Certificate via mkcert for domains: {domains}...")
        cmd = [mkcert_bin, "-cert-file", abs_cert, "-key-file", abs_key] + domains
        res = subprocess.run(cmd, capture_output=True, text=True, errors="ignore")
        if res.returncode == 0:
            print(f"[SUCCESS] Trusted SSL Certificate generated via mkcert:\n  - Cert: {abs_cert}\n  - Key:  {abs_key}\n  - Domains: {domains}")
            return

    # Fallback to cryptography self-signed certificate
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    print(f"[SSL] Generating Self-Signed SSL Certificate for domains/IPs: {domains}...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "AISecurityAudit Self-Signed SSL"),
    ])

    alt_names = []
    for entry in domains:
        entry = entry.strip()
        if not entry:
            continue
        try:
            alt_names.append(x509.IPAddress(ipaddress.ip_address(entry)))
        except ValueError:
            alt_names.append(x509.DNSName(entry))

    if not alt_names:
        alt_names = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
    ).add_extension(
        x509.SubjectAlternativeName(alt_names),
        critical=False,
    ).sign(key, hashes.SHA256())

    with open(abs_cert, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(abs_key, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    print(f"[SUCCESS] SSL Certificate generated:\n  - Cert: {abs_cert}\n  - Key:  {abs_key}")

    if sys.platform == "win32":
        try:
            cmd1 = f'powershell -Command "Import-Certificate -FilePath \'{abs_cert}\' -CertStoreLocation \'Cert:\\CurrentUser\\Root\'"'
            subprocess.run(cmd1, shell=True, capture_output=True, text=True, errors="ignore")
            cmd2 = f'powershell -Command "Import-Certificate -FilePath \'{abs_cert}\' -CertStoreLocation \'Cert:\\LocalMachine\\Root\'"'
            subprocess.run(cmd2, shell=True, capture_output=True, text=True, errors="ignore")
            print("[SUCCESS] Installed SSL Certificate into Windows Trusted Root Store!")
        except Exception:
            pass

if __name__ == "__main__":
    custom_domains = sys.argv[1:] if len(sys.argv) > 1 else [
        "localhost",
        "127.0.0.1",
        "::1"
    ]
    generate_ssl_cert(domains=custom_domains)
