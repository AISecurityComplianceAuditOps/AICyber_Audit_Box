import os
from cryptography.fernet import Fernet

KEY_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config", "mcp_master.key")

def _get_or_create_key() -> bytes:
    if not os.path.exists(KEY_FILE):
        os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key
    else:
        with open(KEY_FILE, "rb") as f:
            return f.read().strip()

_fernet = Fernet(_get_or_create_key())

def encrypt_credential(credential: str) -> str:
    if not credential:
        return ""
    return _fernet.encrypt(credential.encode("utf-8")).decode("utf-8")

def decrypt_credential(encrypted_credential: str) -> str:
    if not encrypted_credential:
        return ""
    try:
        return _fernet.decrypt(encrypted_credential.encode("utf-8")).decode("utf-8")
    except Exception:
        return ""
