"""
MTProto key exchange (handshake) handler.
Implements the full DH key exchange protocol:
  1. Client -> req_pq_multi -> Server responds with resPQ (pq, server_nonce, fingerprints)
  2. Client -> req_DH_params -> Server responds with server_DH_params_ok (encrypted DH params)
  3. Client -> set_client_DH_params -> Server responds with dh_gen_ok/fail/retry
"""

import os
import struct
import hashlib
import logging
from Crypto.Util.number import long_to_bytes, bytes_to_long

from mtproto_server.tl_serialization import TLSerializer, TLDeserializer
from mtproto_server import crypto

logger = logging.getLogger(__name__)

# TL constructors for handshake
CID_REQ_PQ_MULTI = 0xbe7e8ef1
CID_REQ_DH_PARAMS = 0xd712e4be
CID_SET_CLIENT_DH_PARAMS = 0xf5045f1f

CID_RES_PQ = 0x05162463
CID_SERVER_DH_PARAMS_OK = 0xd0e8075c
CID_SERVER_DH_PARAMS_FAIL = 0x79cb045d
CID_SERVER_DH_INNER_DATA = 0xb5890dba
CID_DH_GEN_OK = 0x3bcbf734
CID_DH_GEN_RETRY = 0x46dc1fb9
CID_DH_GEN_FAIL = 0xa69dae02

CID_P_Q_INNER_DATA = 0x83c95aec
CID_P_Q_INNER_DATA_DC = 0xa9f55f95
CID_P_Q_INNER_DATA_TEMP = 0x3c6a84d4
CID_P_Q_INNER_DATA_TEMP_DC = 0x56fddf88
CID_CLIENT_DH_INNER_DATA = 0x6643b654

# Precomputed PQ for simplicity: p=1724114033, q=1936024747 -> pq = p*q
PQ_VALUE = 1724114033 * 1936024747
P_VALUE = 1724114033
Q_VALUE = 1936024747


class HandshakeState:
    """Tracks state for a single handshake session."""

    def __init__(self):
        self.nonce = None
        self.server_nonce = None
        self.new_nonce = None
        self.pq = PQ_VALUE
        self.p = P_VALUE
        self.q = Q_VALUE
        self.dh_b = None
        self.g_b = None
        self.tmp_aes_key = None
        self.tmp_aes_iv = None
        self.auth_key = None
        self.auth_key_id = None
        self.temp_key_expires_in = 0
        self.is_temp_key = False


def handle_req_pq_multi(data: bytes, state: HandshakeState) -> bytes:
    """Handle req_pq_multi: respond with resPQ."""
    reader = TLDeserializer(data)
    constructor = reader.read_uint32()
    nonce = reader.read_int128()

    state.nonce = nonce
    state.server_nonce = os.urandom(16)

    pq_bytes = long_to_bytes(state.pq)

    fingerprint = crypto.get_rsa_fingerprint()

    writer = TLSerializer()
    writer.write_uint32(CID_RES_PQ)
    writer.write_int128(state.nonce)
    writer.write_int128(state.server_nonce)
    writer.write_bytes(pq_bytes)

    # vector of fingerprints
    writer.write_uint32(0x1cb5c415)  # vector
    writer.write_int32(1)
    writer.write_int64(fingerprint)

    return writer.get_bytes()


def handle_req_dh_params(data: bytes, state: HandshakeState) -> bytes:
    """Handle req_DH_params: decrypt p_q_inner_data, respond with server DH params."""
    reader = TLDeserializer(data)
    constructor = reader.read_uint32()
    nonce = reader.read_int128()
    server_nonce = reader.read_int128()
    p_bytes = reader.read_bytes()
    q_bytes = reader.read_bytes()
    fingerprint = reader.read_int64()
    encrypted_data = reader.read_bytes()

    logger.info(f"req_dh_params: encrypted_data_len={len(encrypted_data)}, fingerprint=0x{fingerprint & 0xFFFFFFFFFFFFFFFF:016x}")

    if nonce != state.nonce or server_nonce != state.server_nonce:
        logger.error(f"Nonce mismatch in req_DH_params: nonce_match={nonce == state.nonce}, sn_match={server_nonce == state.server_nonce}")
        return _build_dh_params_fail(state)

    # Decrypt the encrypted_data with RSA
    decrypted = crypto.rsa_decrypt(encrypted_data)
    logger.info(f"RSA decrypted: len={len(decrypted)}, first16={decrypted[:16].hex()}")

    # MTProto 2.0 RSA padding format:
    key_aes_encrypted = decrypted[:32]
    aes_encrypted_data = decrypted[32:]

    key_hash = hashlib.sha256(aes_encrypted_data).digest()
    key = bytes(a ^ b for a, b in zip(key_aes_encrypted, key_hash))

    iv = b'\x00' * 32
    aes_decrypted = crypto.aes_ige_decrypt(aes_encrypted_data, key, iv)

    reversed_padded_data = aes_decrypted[:192]
    data_hash = aes_decrypted[192:224]

    padded_data = bytes(reversed(reversed_padded_data))

    expected_hash = hashlib.sha256(key + padded_data).digest()
    hash_ok = data_hash == expected_hash
    logger.info(f"MTProto 2.0 hash verification: {hash_ok}")

    if not hash_ok:
        logger.warning("RSA inner data hash mismatch, trying legacy format")
        inner_reader = TLDeserializer(decrypted[20:])
    else:
        inner_reader = TLDeserializer(padded_data)

    inner_constructor = inner_reader.read_uint32()
    logger.info(f"Inner constructor: 0x{inner_constructor:08x}")

    inner_pq = inner_reader.read_bytes()
    inner_p = inner_reader.read_bytes()
    inner_q = inner_reader.read_bytes()
    inner_nonce = inner_reader.read_int128()
    inner_server_nonce = inner_reader.read_int128()
    new_nonce = inner_reader.read_int256()

    logger.info(f"Inner nonce match: {inner_nonce == state.nonce}, inner_sn match: {inner_server_nonce == state.server_nonce}")
    logger.info(f"new_nonce: {new_nonce[:8].hex()}..., is_temp={inner_constructor in (CID_P_Q_INNER_DATA_TEMP, CID_P_Q_INNER_DATA_TEMP_DC)}")

    state.new_nonce = new_nonce
    state.is_temp_key = inner_constructor in (CID_P_Q_INNER_DATA_TEMP, CID_P_Q_INNER_DATA_TEMP_DC)

    if inner_constructor in (CID_P_Q_INNER_DATA_DC, CID_P_Q_INNER_DATA_TEMP_DC):
        try:
            dc_id = inner_reader.read_int32()
            logger.info(f"DC ID: {dc_id}")
        except Exception:
            pass

    if state.is_temp_key:
        try:
            state.temp_key_expires_in = inner_reader.read_int32()
        except Exception:
            state.temp_key_expires_in = 86400

    state.dh_b, g_b_int = crypto.generate_dh_params()
    state.g_b = g_b_int

    tmp_aes_key, tmp_aes_iv = _compute_tmp_aes(state.server_nonce, new_nonce)
    state.tmp_aes_key = tmp_aes_key
    state.tmp_aes_iv = tmp_aes_iv
    logger.info(f"tmp_aes_key len={len(tmp_aes_key)}, tmp_aes_iv len={len(tmp_aes_iv)}")

    inner_writer = TLSerializer()
    inner_writer.write_uint32(CID_SERVER_DH_INNER_DATA)
    inner_writer.write_int128(state.nonce)
    inner_writer.write_int128(state.server_nonce)
    inner_writer.write_int32(crypto.DH_GENERATOR)
    inner_writer.write_bytes(long_to_bytes(crypto.DH_PRIME, 256))
    inner_writer.write_bytes(long_to_bytes(g_b_int, 256))
    inner_writer.write_int32(int(import_time()))

    inner_bytes = inner_writer.get_bytes()

    inner_hash = hashlib.sha1(inner_bytes).digest()
    answer_data = inner_hash + inner_bytes
    padding_len = (16 - len(answer_data) % 16) % 16
    answer_data += os.urandom(padding_len)
    logger.info(f"DH answer_data len={len(answer_data)} (before encrypt)")

    encrypted_answer = crypto.aes_ige_encrypt(answer_data, tmp_aes_key, tmp_aes_iv)

    writer = TLSerializer()
    writer.write_uint32(CID_SERVER_DH_PARAMS_OK)
    writer.write_int128(state.nonce)
    writer.write_int128(state.server_nonce)
    writer.write_bytes(encrypted_answer)

    logger.info(f"server_DH_params_ok response built, len={len(writer.get_bytes())}")
    return writer.get_bytes()


def handle_set_client_dh_params(data: bytes, state: HandshakeState) -> bytes:
    """Handle set_client_DH_params: compute auth_key, respond with dh_gen_ok."""
    reader = TLDeserializer(data)
    constructor = reader.read_uint32()
    nonce = reader.read_int128()
    server_nonce = reader.read_int128()
    encrypted_data = reader.read_bytes()

    if nonce != state.nonce or server_nonce != state.server_nonce:
        logger.error("Nonce mismatch in set_client_DH_params")
        return _build_dh_gen_fail(state)

    # Decrypt with tmp AES key/iv
    decrypted = crypto.aes_ige_decrypt(encrypted_data, state.tmp_aes_key, state.tmp_aes_iv)

    # Parse: SHA1(data) + client_DH_inner_data
    inner_hash = decrypted[:20]
    inner_reader = TLDeserializer(decrypted[20:])
    inner_constructor = inner_reader.read_uint32()  # client_DH_inner_data
    inner_nonce = inner_reader.read_int128()
    inner_server_nonce = inner_reader.read_int128()
    retry_id = inner_reader.read_int64()
    g_b_bytes = inner_reader.read_bytes()

    g_a = bytes_to_long(g_b_bytes)

    # Compute auth_key
    auth_key = crypto.compute_auth_key(g_a, state.dh_b)
    auth_key_id = crypto.compute_auth_key_id(auth_key)
    auth_key_aux_hash = crypto.compute_auth_key_aux_hash(auth_key)

    state.auth_key = auth_key
    state.auth_key_id = auth_key_id

    # Compute new_nonce_hash1
    new_nonce_hash1 = _compute_new_nonce_hash(state.new_nonce, 1, auth_key_aux_hash)

    # Build dh_gen_ok response
    writer = TLSerializer()
    writer.write_uint32(CID_DH_GEN_OK)
    writer.write_int128(state.nonce)
    writer.write_int128(state.server_nonce)
    writer.write_int128(new_nonce_hash1)

    logger.info(f"Handshake complete, auth_key_id=0x{auth_key_id & 0xFFFFFFFFFFFFFFFF:016x}")
    return writer.get_bytes()


def _compute_tmp_aes(server_nonce: bytes, new_nonce: bytes) -> tuple:
    """Compute tmp_aes_key and tmp_aes_iv from server_nonce and new_nonce."""
    hash1 = hashlib.sha1(new_nonce + server_nonce).digest()
    hash2 = hashlib.sha1(server_nonce + new_nonce).digest()
    hash3 = hashlib.sha1(new_nonce + new_nonce).digest()

    tmp_aes_key = hash1 + hash2[:12]
    tmp_aes_iv = hash2[12:] + hash3 + new_nonce[:4]

    return tmp_aes_key, tmp_aes_iv


def _compute_new_nonce_hash(new_nonce: bytes, num: int, auth_key_aux_hash: bytes) -> bytes:
    """Compute new_nonce_hash for dh_gen_ok/retry/fail."""
    data = new_nonce + struct.pack('<B', num) + auth_key_aux_hash
    return hashlib.sha1(data).digest()[4:]


def _build_dh_params_fail(state: HandshakeState) -> bytes:
    writer = TLSerializer()
    writer.write_uint32(CID_SERVER_DH_PARAMS_FAIL)
    writer.write_int128(state.nonce)
    writer.write_int128(state.server_nonce)
    writer.write_int128(os.urandom(16))
    return writer.get_bytes()


def _build_dh_gen_fail(state: HandshakeState) -> bytes:
    writer = TLSerializer()
    writer.write_uint32(CID_DH_GEN_FAIL)
    writer.write_int128(state.nonce)
    writer.write_int128(state.server_nonce)
    writer.write_int128(os.urandom(16))
    return writer.get_bytes()


def import_time():
    import time
    return time.time()
