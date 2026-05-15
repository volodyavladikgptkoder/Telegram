"""
MTProto cryptographic operations:
- RSA key generation and encryption
- AES-IGE mode encryption/decryption
- SHA1/SHA256 hashing
- DH parameter generation
- Auth key derivation
"""

import os
import hashlib
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long


# Server RSA key pair (2048-bit) — generated once at startup
_rsa_key = None
_rsa_key_fingerprint = None


def get_server_rsa_key() -> RSA.RsaKey:
    global _rsa_key
    if _rsa_key is None:
        key_path = os.path.join(os.path.dirname(__file__), '..', 'server_key.pem')
        if os.path.exists(key_path):
            with open(key_path, 'rb') as f:
                _rsa_key = RSA.import_key(f.read())
        else:
            _rsa_key = RSA.generate(2048)
            with open(key_path, 'wb') as f:
                f.write(_rsa_key.export_key('PEM'))
    return _rsa_key


def get_server_public_key_pem() -> str:
    key = get_server_rsa_key()
    n_bytes = long_to_bytes(key.n)
    e_bytes = long_to_bytes(key.e)

    def encode_tl_bytes(data: bytes) -> bytes:
        length = len(data)
        if length < 254:
            return struct.pack('<B', length) + data + b'\x00' * ((4 - (length + 1) % 4) % 4)
        else:
            return b'\xfe' + struct.pack('<I', length)[:3] + data + b'\x00' * ((4 - length % 4) % 4)

    return key.public_key().export_key('PEM').decode()


def get_rsa_fingerprint() -> int:
    global _rsa_key_fingerprint
    if _rsa_key_fingerprint is None:
        key = get_server_rsa_key()
        from mtproto_server.tl_serialization import TLSerializer
        s = TLSerializer()
        n_bytes = long_to_bytes(key.n)
        e_bytes = long_to_bytes(key.e)
        s.write_bytes(n_bytes)
        s.write_bytes(e_bytes)
        sha1_hash = hashlib.sha1(s.get_bytes()).digest()
        _rsa_key_fingerprint = struct.unpack('<q', sha1_hash[-8:])[0]
    return _rsa_key_fingerprint


def rsa_decrypt(data: bytes) -> bytes:
    key = get_server_rsa_key()
    encrypted_int = bytes_to_long(data)
    decrypted_int = pow(encrypted_int, key.d, key.n)
    return long_to_bytes(decrypted_int, 256)


def rsa_encrypt(data: bytes) -> bytes:
    key = get_server_rsa_key()
    data_int = bytes_to_long(data)
    encrypted_int = pow(data_int, key.e, key.n)
    return long_to_bytes(encrypted_int, 256)


def sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def aes_ige_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-IGE encryption."""
    assert len(key) == 32
    assert len(iv) == 32

    aes_cipher = AES.new(key, AES.MODE_ECB)
    iv_p = iv[:16]
    iv_c = iv[16:]

    padding = (16 - len(data) % 16) % 16
    if padding:
        data = data + os.urandom(padding)

    encrypted = bytearray()
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        xored = bytes(a ^ b for a, b in zip(block, iv_c))
        enc_block = aes_cipher.encrypt(xored)
        enc_block = bytes(a ^ b for a, b in zip(enc_block, iv_p))
        encrypted += enc_block
        iv_p = block
        iv_c = enc_block

    return bytes(encrypted)


def aes_ige_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-IGE decryption."""
    assert len(key) == 32
    assert len(iv) == 32

    aes_cipher = AES.new(key, AES.MODE_ECB)
    iv_p = iv[:16]
    iv_c = iv[16:]

    decrypted = bytearray()
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        xored = bytes(a ^ b for a, b in zip(block, iv_p))
        dec_block = aes_cipher.decrypt(xored)
        dec_block = bytes(a ^ b for a, b in zip(dec_block, iv_c))
        decrypted += dec_block
        iv_c = block
        iv_p = dec_block

    return bytes(decrypted)


def generate_nonce(size: int = 16) -> bytes:
    return os.urandom(size)


def compute_msg_key(auth_key: bytes, data: bytes, is_from_client: bool) -> bytes:
    """Compute msg_key for MTProto 2.0."""
    x = 0 if not is_from_client else 8
    msg_key_large = sha256(auth_key[88 + x:88 + x + 32] + data)
    return msg_key_large[8:24]


def compute_aes_key_iv(auth_key: bytes, msg_key: bytes, is_from_client: bool) -> tuple:
    """Compute AES key and IV from auth_key and msg_key for MTProto 2.0."""
    x = 0 if not is_from_client else 8
    sha256_a = sha256(msg_key + auth_key[x:x + 36])
    sha256_b = sha256(auth_key[40 + x:40 + x + 36] + msg_key)

    aes_key = sha256_a[:8] + sha256_b[8:24] + sha256_a[24:32]
    aes_iv = sha256_b[:8] + sha256_a[8:24] + sha256_b[24:32]
    return aes_key, aes_iv


# Well-known 2048-bit DH prime (same as in Telegram)
DH_PRIME_HEX = (
    "c71caeb9c6b1c9048e6c522f70f13f73980d40238e3e21c14934d037563d930f"
    "48198a0aa7c14058229493d22530f4dbfa336f6e0ac925139543aed44cce7c37"
    "20fd51f69458705ac68cd4fe6b6b13abdc9746512969328454f18faf8c595f64"
    "2477fe96bb2a941d5bcd1d4ac8cc49880708fa9b378e3c4f3a9060bee67cf9a4"
    "a4a695811051907e162753b56b0f6b410dba74d8a84b2a14b3144e0ef1284754"
    "fd17ed950d5965b4b9dd46582db1178d169c6bc465b0d6ff9ca3928fef5b9ae4"
    "e418fc15e83ebea0f87fa9ff5eed70050ded2849f47bf959d956850ce929851f"
    "0d8115f635b105ee2e4e15d04b2454bf6f4fadf034b10403119cd8e3b92fcc5b"
)
DH_PRIME = int(DH_PRIME_HEX, 16)
DH_GENERATOR = 3


def generate_dh_params() -> tuple:
    """Generate server DH parameters (b, g_b)."""
    b = bytes_to_long(os.urandom(256)) % DH_PRIME
    g_b = pow(DH_GENERATOR, b, DH_PRIME)
    return b, g_b


def compute_auth_key(g_a: int, b: int) -> bytes:
    """Compute auth_key = g_a^b mod p."""
    auth_key_int = pow(g_a, b, DH_PRIME)
    return long_to_bytes(auth_key_int, 256)


def compute_auth_key_id(auth_key: bytes) -> int:
    """auth_key_id = lower 64 bits of SHA1(auth_key)."""
    return struct.unpack('<q', sha1(auth_key)[-8:])[0]


def compute_auth_key_aux_hash(auth_key: bytes) -> bytes:
    """First 8 bytes of SHA1(auth_key)."""
    return sha1(auth_key)[:8]
