"""
MTProto message framing and encryption/decryption.
Handles:
- Unencrypted messages (auth_key_id == 0) for handshake
- Encrypted messages (auth_key_id != 0) for API calls
- Message containers (msg_container)
"""

import struct
import os
import time
import logging
import hashlib

from mtproto_server.tl_serialization import TLSerializer, TLDeserializer
from mtproto_server import crypto

logger = logging.getLogger(__name__)

MSG_CONTAINER = 0x73f1f8dc
RPC_RESULT = 0xf35c6d01
RPC_ERROR = 0x2144ca19
GZIP_PACKED = 0x3072cfa1
MSGS_ACK = 0x62d6b459


class MTProtoMessage:
    """Represents a parsed MTProto message."""

    def __init__(self):
        self.auth_key_id = 0
        self.msg_id = 0
        self.seq_no = 0
        self.data = b''
        self.constructor = 0
        self.session_id = 0
        self.server_salt = 0


def parse_unencrypted_message(raw_data: bytes) -> MTProtoMessage:
    """Parse an unencrypted MTProto message (used during handshake)."""
    msg = MTProtoMessage()
    reader = TLDeserializer(raw_data)

    msg.auth_key_id = reader.read_int64()  # should be 0
    msg.msg_id = reader.read_int64()
    data_length = reader.read_int32()
    msg.data = reader.read_raw(data_length)

    if len(msg.data) >= 4:
        msg.constructor = struct.unpack_from('<I', msg.data, 0)[0]

    return msg


def build_unencrypted_response(data: bytes, msg_id: int = None) -> bytes:
    """Build an unencrypted MTProto response."""
    if msg_id is None:
        msg_id = generate_msg_id()

    writer = TLSerializer()
    writer.write_int64(0)  # auth_key_id = 0
    writer.write_int64(msg_id)
    writer.write_int32(len(data))
    writer.write_raw(data)

    return writer.get_bytes()


def decrypt_message(raw_data: bytes, auth_key: bytes) -> MTProtoMessage:
    """Decrypt an encrypted MTProto message."""
    msg = MTProtoMessage()
    reader = TLDeserializer(raw_data)

    msg.auth_key_id = reader.read_int64()
    msg_key = reader.read_raw(16)
    encrypted_data = reader.read_raw(reader.remaining)

    # Compute AES key/IV (from client -> x=8)
    aes_key, aes_iv = crypto.compute_aes_key_iv(auth_key, msg_key, is_from_client=True)

    # Decrypt
    decrypted = crypto.aes_ige_decrypt(encrypted_data, aes_key, aes_iv)

    # Parse decrypted data
    inner_reader = TLDeserializer(decrypted)
    msg.server_salt = inner_reader.read_int64()
    msg.session_id = inner_reader.read_int64()
    msg.msg_id = inner_reader.read_int64()
    msg.seq_no = inner_reader.read_int32()
    data_length = inner_reader.read_int32()
    msg.data = inner_reader.read_raw(data_length)

    if len(msg.data) >= 4:
        msg.constructor = struct.unpack_from('<I', msg.data, 0)[0]

    return msg


def encrypt_message(data: bytes, auth_key: bytes, session_id: int, server_salt: int, msg_id: int = None, seq_no: int = 0) -> bytes:
    """Encrypt a message for sending to the client."""
    if msg_id is None:
        msg_id = generate_msg_id()

    # Build inner data: server_salt + session_id + msg_id + seq_no + data_length + data + padding
    inner = TLSerializer()
    inner.write_int64(server_salt)
    inner.write_int64(session_id)
    inner.write_int64(msg_id)
    inner.write_int32(seq_no)
    inner.write_int32(len(data))
    inner.write_raw(data)

    inner_bytes = inner.get_bytes()

    # Add random padding (12..1024 bytes, aligned to 16)
    padding_len = 12 + (16 - (len(inner_bytes) + 12) % 16) % 16
    inner_bytes += os.urandom(padding_len)

    # Compute msg_key (server -> client, x=0)
    msg_key = crypto.compute_msg_key(auth_key, inner_bytes, is_from_client=False)

    # Compute AES key/IV (server -> client, x=0)
    aes_key, aes_iv = crypto.compute_aes_key_iv(auth_key, msg_key, is_from_client=False)

    # Encrypt
    encrypted = crypto.aes_ige_encrypt(inner_bytes, aes_key, aes_iv)

    # Build outer message
    auth_key_id = crypto.compute_auth_key_id(auth_key)
    outer = TLSerializer()
    outer.write_int64(auth_key_id)
    outer.write_raw(msg_key)
    outer.write_raw(encrypted)

    return outer.get_bytes()


def build_rpc_result(req_msg_id: int, result_data: bytes) -> bytes:
    """Wrap a response in rpc_result."""
    writer = TLSerializer()
    writer.write_uint32(RPC_RESULT)
    writer.write_int64(req_msg_id)
    writer.write_raw(result_data)
    return writer.get_bytes()


def build_rpc_error(req_msg_id: int, error_code: int, error_message: str) -> bytes:
    """Build an rpc_error response."""
    error_writer = TLSerializer()
    error_writer.write_uint32(RPC_ERROR)
    error_writer.write_int32(error_code)
    error_writer.write_string(error_message)

    writer = TLSerializer()
    writer.write_uint32(RPC_RESULT)
    writer.write_int64(req_msg_id)
    writer.write_raw(error_writer.get_bytes())
    return writer.get_bytes()


def build_msgs_ack(msg_ids: list) -> bytes:
    """Build msgs_ack."""
    writer = TLSerializer()
    writer.write_uint32(MSGS_ACK)
    writer.write_uint32(0x1cb5c415)  # vector
    writer.write_int32(len(msg_ids))
    for mid in msg_ids:
        writer.write_int64(mid)
    return writer.get_bytes()


def build_msg_container(messages: list) -> bytes:
    """Build a msg_container with multiple messages."""
    writer = TLSerializer()
    writer.write_uint32(MSG_CONTAINER)
    writer.write_int32(len(messages))
    for msg_id, seq_no, data in messages:
        writer.write_int64(msg_id)
        writer.write_int32(seq_no)
        writer.write_int32(len(data))
        writer.write_raw(data)
    return writer.get_bytes()


_msg_id_counter = 0


def generate_msg_id() -> int:
    """Generate a unique message ID (server-side: must be divisible by 4 with remainder 1)."""
    global _msg_id_counter
    t = int(time.time())
    msg_id = (t << 32) | (_msg_id_counter << 2) | 1
    _msg_id_counter = (_msg_id_counter + 1) % (2**30)
    return msg_id
