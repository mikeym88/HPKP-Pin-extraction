from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat
import ssl
import socket
from ssl import SSLContext
import hashlib
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def generate_hpkp_from_pem_certificate(pem_cert: str) -> str:
    cert = x509.load_pem_x509_certificate(pem_cert.encode("utf-8"), default_backend())
    encryption = cert.signature_hash_algorithm.name  # e.g. SHA-1, SHA-256
    cert_subject_public_key_info = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    encryption_formatted = encryption.replace("-", "").lower()
    if encryption_formatted == "sha256":
        m = hashlib.sha256()
        prefix = "sha256/"
    elif encryption_formatted == "sha1":
        m = hashlib.sha1()
        prefix = "sha1/"
    else:
        raise Exception("Invalid path")

    if prefix and m:
        m.update(cert_subject_public_key_info)
        digest = m.digest()
        digest_base64 = base64.b64encode(digest)
        digest_str = digest_base64.decode("utf-8")

        return prefix + digest_str
