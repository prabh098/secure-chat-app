# crypto_utils.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asympad
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64

# ---------- RSA ----------
def generate_rsa_keypair() -> tuple[rsa.RSAPrivateKey, bytes]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem

def rsa_encrypt_oaep(pub_pem: bytes, data: bytes) -> bytes:
    pub = serialization.load_pem_public_key(pub_pem)
    return pub.encrypt(
        data,
        asympad.OAEP(
            mgf=asympad.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def rsa_decrypt_oaep(priv: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return priv.decrypt(
        data,
        asympad.OAEP(
            mgf=asympad.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

# ---------- AES-GCM ----------
@dataclass
class AesSession:
    key: bytes  # 32 bytes for AES-256

    @staticmethod
    def new() -> "AesSession":
        return AesSession(key=AESGCM.generate_key(bit_length=256))

    def encrypt(self, plaintext: bytes, aad: Optional[bytes]=None) -> tuple[bytes, bytes]:
        """
        Returns (nonce, ciphertext_with_tag). AESGCM appends tag to ciphertext.
        """
        nonce = os.urandom(12)
        ct = AESGCM(self.key).encrypt(nonce, plaintext, aad)
        return nonce, ct

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: Optional[bytes]=None) -> bytes:
        return AESGCM(self.key).decrypt(nonce, ciphertext, aad)

# ---------- helpers ----------
def b64e(b: bytes) -> str: return base64.b64encode(b).decode("utf-8")
def b64d(s: str) -> bytes: return base64.b64decode(s.encode("utf-8"))
