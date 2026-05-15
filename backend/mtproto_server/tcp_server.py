"""
MTProto TCP server — handles raw TCP connections from Telegram clients.
Supports:
- Abridged transport (1-byte length prefix)
- Intermediate transport (4-byte length prefix)
- Padded intermediate (4-byte length prefix + padding)
- Full transport (12-byte header)

Each connection goes through handshake then processes encrypted RPC requests.
"""

import asyncio
import struct
import logging
import traceback
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from mtproto_server.handshake import HandshakeState, handle_req_pq_multi, handle_req_dh_params, handle_set_client_dh_params
from mtproto_server.handshake import CID_REQ_PQ_MULTI, CID_REQ_DH_PARAMS, CID_SET_CLIENT_DH_PARAMS
from mtproto_server.message_processor import (
    parse_unencrypted_message, build_unencrypted_response,
    decrypt_message, encrypt_message, build_rpc_result, build_rpc_error,
    build_msgs_ack, generate_msg_id, MSG_CONTAINER, MSGS_ACK
)
from mtproto_server.rpc_handlers import RPCContext, dispatch_rpc, unwrap_layers
from mtproto_server import database as db
from mtproto_server import crypto

logger = logging.getLogger(__name__)

# Transport types detected by first byte(s)
TRANSPORT_ABRIDGED = 1
TRANSPORT_INTERMEDIATE = 2
TRANSPORT_PADDED_INTERMEDIATE = 3
TRANSPORT_FULL = 4

# ============================================================
# Connection Registry for real-time push
# ============================================================
# Maps user_id -> set of ClientConnection objects
_user_connections: dict[int, set] = {}
_connections_lock = asyncio.Lock() if hasattr(asyncio, 'Lock') else None
import collections
_rate_limits: dict[int, list] = collections.defaultdict(list)
RATE_LIMIT_WINDOW = 1.0  # seconds
RATE_LIMIT_MAX = 30  # max requests per window


def _register_connection(user_id: int, conn):
    if user_id not in _user_connections:
        _user_connections[user_id] = set()
    _user_connections[user_id].add(conn)
    logger.info(f"Registered connection for user {user_id}, total: {len(_user_connections[user_id])}")


def _unregister_connection(user_id: int, conn):
    if user_id in _user_connections:
        _user_connections[user_id].discard(conn)
        if not _user_connections[user_id]:
            del _user_connections[user_id]
        logger.info(f"Unregistered connection for user {user_id}")


def push_update_to_user(user_id: int, update_data: bytes):
    """Push an update to all connections of a user (called from handlers)."""
    if user_id not in _user_connections:
        return
    for conn in list(_user_connections[user_id]):
        asyncio.ensure_future(conn._push_update(update_data))


def _check_rate_limit(user_id: int) -> bool:
    """Returns True if within rate limit, False if exceeded."""
    import time
    now = time.time()
    timestamps = _rate_limits[user_id]
    # Remove old entries
    _rate_limits[user_id] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_limits[user_id]) >= RATE_LIMIT_MAX:
        return False
    _rate_limits[user_id].append(now)
    return True


class ClientConnection:
    """Manages state for a single client TCP connection."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.transport_type = None
        self.handshake_states = {}  # nonce -> HandshakeState
        self.auth_key = None
        self.auth_key_id = None
        self.session_id = 0
        self.server_salt = 0
        self.user_id = None
        self.seq_no = 0
        self.addr = writer.get_extra_info('peername')
        self._current_handshake = None
        # Obfuscated transport AES-CTR state
        self._decrypt_encryptor = None  # for decrypting incoming data
        self._encrypt_encryptor = None  # for encrypting outgoing data
        self._obfuscated = False

    async def _push_update(self, update_data: bytes):
        """Send an update to this client through its existing encrypted connection."""
        if not self.auth_key or not self.session_id:
            return
        try:
            encrypted = encrypt_message(
                update_data, self.auth_key, self.session_id,
                self.server_salt, seq_no=self.seq_no
            )
            self.seq_no += 2
            await self._send_message(encrypted)
            logger.debug(f"Pushed update to user {self.user_id}")
        except Exception as e:
            logger.error(f"Failed to push update to user {self.user_id}: {e}")

    async def handle(self):
        logger.info(f"New connection from {self.addr}")
        try:
            await self._detect_transport()
            while True:
                data = await self._read_message()
                if data is None:
                    break
                await self._process_message(data)
        except asyncio.IncompleteReadError:
            pass
        except ConnectionResetError:
            pass
        except Exception as e:
            logger.error(f"Connection error from {self.addr}: {e}")
            traceback.print_exc()
        finally:
            # Unregister from connection registry
            if self.user_id:
                _unregister_connection(self.user_id, self)
            self.writer.close()
            logger.info(f"Connection closed from {self.addr}")

    async def _detect_transport(self):
        """Detect transport type, handling obfuscated (64-byte header) connections."""
        header = await self.reader.readexactly(64)

        # Check if this looks like an obfuscated header.
        # Obfuscated headers have 64 random bytes where bytes[56:60] encode the protocol
        # after decryption.  We detect obfuscation by trying to decrypt and checking
        # the protocol marker.
        first4 = struct.unpack('<I', header[:4])[0]
        second4 = struct.unpack('<I', header[4:8])[0]

        # Plain-text markers that would appear in non-obfuscated connections
        plain_markers = {0xefefefef, 0xeeeeeeee, 0xdddddddd, 0x44414548, 0x54534f50, 0x20544547, 0x4954504f, 0x02010316}
        if first4 in plain_markers or header[0] == 0xef or second4 == 0x00000000:
            # Non-obfuscated: fall back to legacy detection
            await self._detect_plain_transport(header)
            return

        # Obfuscated transport: derive keys from the 64-byte init payload
        # Server decrypt key (= client encrypt key): bytes[8:40] key, bytes[40:56] IV
        decrypt_key = header[8:40]
        decrypt_iv = bytearray(header[40:56])

        # Server encrypt key (= client decrypt key): reverse of bytes[8:56]
        rev = header[55:7:-1]  # bytes 55,54,...,8  (48 bytes)
        encrypt_key = bytes(rev[:32])
        encrypt_iv = bytearray(rev[32:48])

        # Build AES-CTR decryptor
        dec_cipher = Cipher(algorithms.AES(decrypt_key), modes.CTR(bytes(decrypt_iv)), backend=default_backend())
        self._decrypt_encryptor = dec_cipher.encryptor()

        # Decrypt the original 64 bytes to read the protocol marker
        decrypted_header = self._decrypt_encryptor.update(header)

        # Build AES-CTR encryptor
        enc_cipher = Cipher(algorithms.AES(encrypt_key), modes.CTR(bytes(encrypt_iv)), backend=default_backend())
        self._encrypt_encryptor = enc_cipher.encryptor()

        self._obfuscated = True

        # Protocol marker is at decrypted bytes [56:60]
        marker = struct.unpack('<I', decrypted_header[56:60])[0]
        if marker == 0xefefefef:
            self.transport_type = TRANSPORT_ABRIDGED
        elif marker == 0xeeeeeeee:
            self.transport_type = TRANSPORT_INTERMEDIATE
        elif marker == 0xdddddddd:
            self.transport_type = TRANSPORT_PADDED_INTERMEDIATE
        else:
            self.transport_type = TRANSPORT_ABRIDGED

        logger.debug(f"{self.addr}: Obfuscated transport detected, protocol=0x{marker:08x}, type={self.transport_type}")

    async def _detect_plain_transport(self, header: bytes):
        """Legacy non-obfuscated transport detection."""
        b = header[0]
        if b == 0xef:
            self.transport_type = TRANSPORT_ABRIDGED
            # remaining 63 bytes might be part of the first message
            leftover = header[1:]
            if leftover:
                self._plain_leftover = leftover
        elif header[:4] == b'\xee\xee\xee\xee':
            self.transport_type = TRANSPORT_INTERMEDIATE
            leftover = header[4:]
            if leftover:
                self._plain_leftover = leftover
        elif header[:4] == b'\xdd\xdd\xdd\xdd':
            self.transport_type = TRANSPORT_PADDED_INTERMEDIATE
            leftover = header[4:]
            if leftover:
                self._plain_leftover = leftover
        else:
            self.transport_type = TRANSPORT_FULL
            self._plain_leftover = header

    async def _read_raw(self, n: int) -> bytes:
        """Read n bytes, decrypting if obfuscated."""
        data = await self.reader.readexactly(n)
        if self._obfuscated and self._decrypt_encryptor:
            data = self._decrypt_encryptor.update(data)
        return data

    async def _read_message(self) -> bytes:
        """Read a single message according to the transport type."""
        try:
            if self.transport_type == TRANSPORT_ABRIDGED:
                first = await self._read_raw(1)
                length = first[0]
                if length >= 0x7f:
                    length_bytes = await self._read_raw(3)
                    length = struct.unpack('<I', length_bytes + b'\x00')[0]
                length *= 4
                data = await self._read_raw(length)
                return data

            elif self.transport_type == TRANSPORT_INTERMEDIATE:
                length_bytes = await self._read_raw(4)
                length = struct.unpack('<I', length_bytes)[0]
                data = await self._read_raw(length)
                return data

            elif self.transport_type == TRANSPORT_PADDED_INTERMEDIATE:
                length_bytes = await self._read_raw(4)
                length = struct.unpack('<I', length_bytes)[0]
                data = await self._read_raw(length)
                return data

            elif self.transport_type == TRANSPORT_FULL:
                length_bytes = await self._read_raw(4)
                length = struct.unpack('<I', length_bytes)[0]
                remaining = await self._read_raw(length - 4)
                data = remaining[4:-4]
                return data

        except asyncio.IncompleteReadError:
            return None

    def _encrypt_and_write(self, data: bytes):
        """Write data, encrypting if obfuscated."""
        if self._obfuscated and self._encrypt_encryptor:
            data = self._encrypt_encryptor.update(data)
        self.writer.write(data)

    async def _send_message(self, data: bytes):
        """Send a message according to the transport type."""
        if self.transport_type == TRANSPORT_ABRIDGED:
            length = len(data) // 4
            if length < 0x7f:
                self._encrypt_and_write(struct.pack('<B', length))
            else:
                self._encrypt_and_write(b'\x7f' + struct.pack('<I', length)[:3])
            self._encrypt_and_write(data)

        elif self.transport_type == TRANSPORT_INTERMEDIATE:
            self._encrypt_and_write(struct.pack('<I', len(data)))
            self._encrypt_and_write(data)

        elif self.transport_type == TRANSPORT_PADDED_INTERMEDIATE:
            self._encrypt_and_write(struct.pack('<I', len(data)))
            self._encrypt_and_write(data)

        elif self.transport_type == TRANSPORT_FULL:
            seqno = self.seq_no
            self.seq_no += 1
            total_len = 4 + 4 + len(data) + 4
            header = struct.pack('<II', total_len, seqno)
            body = header + data
            import binascii
            crc = binascii.crc32(body)
            self._encrypt_and_write(body + struct.pack('<I', crc))

        await self.writer.drain()

    async def _process_message(self, raw_data: bytes):
        """Process a raw MTProto message (unencrypted or encrypted)."""
        if len(raw_data) < 8:
            return

        auth_key_id = struct.unpack_from('<q', raw_data, 0)[0]

        if auth_key_id == 0:
            # Unencrypted message (handshake)
            await self._handle_unencrypted(raw_data)
        else:
            # Encrypted message (API call)
            await self._handle_encrypted(raw_data)

    async def _handle_unencrypted(self, raw_data: bytes):
        """Handle unencrypted messages during handshake."""
        msg = parse_unencrypted_message(raw_data)
        constructor = msg.constructor

        if constructor == CID_REQ_PQ_MULTI:
            state = HandshakeState()
            response = handle_req_pq_multi(msg.data, state)
            self._current_handshake = state
            await self._send_message(build_unencrypted_response(response))

        elif constructor == CID_REQ_DH_PARAMS:
            if self._current_handshake:
                response = handle_req_dh_params(msg.data, self._current_handshake)
                await self._send_message(build_unencrypted_response(response))

        elif constructor == CID_SET_CLIENT_DH_PARAMS:
            if self._current_handshake:
                response = handle_set_client_dh_params(msg.data, self._current_handshake)
                await self._send_message(build_unencrypted_response(response))

                if self._current_handshake.auth_key:
                    self.auth_key = self._current_handshake.auth_key
                    self.auth_key_id = self._current_handshake.auth_key_id
                    self.server_salt = int.from_bytes(
                        bytes(a ^ b for a, b in zip(
                            self._current_handshake.new_nonce[:8],
                            self._current_handshake.server_nonce[:8]
                        )), 'little', signed=True
                    )

                    conn = db.get_db()
                    is_temp = 1 if self._current_handshake.is_temp_key else 0
                    expires = self._current_handshake.temp_key_expires_in
                    conn.execute("""INSERT OR REPLACE INTO auth_keys 
                                   (auth_key_id, auth_key, server_salt, is_temp, expires_at, created_at) 
                                   VALUES (?, ?, ?, ?, ?, ?)""",
                                 (self.auth_key_id, self.auth_key, self.server_salt,
                                  is_temp, int(import_time()) + expires if expires else 0,
                                  int(import_time())))
                    conn.commit()

                    logger.info(f"Auth key established: 0x{self.auth_key_id & 0xFFFFFFFFFFFFFFFF:016x}, temp={is_temp}")
                    self._current_handshake = None
        else:
            logger.warning(f"Unknown unencrypted constructor: 0x{constructor:08x}")

    async def _handle_encrypted(self, raw_data: bytes):
        """Handle encrypted messages (API calls)."""
        auth_key_id = struct.unpack_from('<q', raw_data, 0)[0]

        if self.auth_key is None or self.auth_key_id != auth_key_id:
            conn = db.get_db()
            row = conn.execute("SELECT * FROM auth_keys WHERE auth_key_id = ?", (auth_key_id,)).fetchone()
            if row:
                self.auth_key = bytes(row['auth_key'])
                self.auth_key_id = auth_key_id
                self.server_salt = row['server_salt']
                self.user_id = row['user_id']
            else:
                logger.error(f"Unknown auth_key_id: 0x{auth_key_id & 0xFFFFFFFFFFFFFFFF:016x}")
                return

        try:
            msg = decrypt_message(raw_data, self.auth_key)
        except Exception as e:
            logger.error(f"Failed to decrypt message: {e}")
            return

        self.session_id = msg.session_id
        self.server_salt = msg.server_salt

        ctx = RPCContext(
            user_id=self.user_id,
            auth_key_id=self.auth_key_id,
            session_id=self.session_id,
            layer=0
        )

        await self._process_rpc(msg.data, msg.msg_id, ctx)

        # Update user_id if changed during auth
        if ctx.user_id and ctx.user_id != self.user_id:
            old_user_id = self.user_id
            self.user_id = ctx.user_id
            # Update connection registry
            if old_user_id:
                _unregister_connection(old_user_id, self)
            _register_connection(self.user_id, self)
            conn = db.get_db()
            conn.execute("UPDATE auth_keys SET user_id = ? WHERE auth_key_id = ?",
                         (self.user_id, self.auth_key_id))
            conn.commit()
        elif ctx.user_id and self.user_id:
            # Ensure we're registered
            if self.user_id not in _user_connections or self not in _user_connections.get(self.user_id, set()):
                _register_connection(self.user_id, self)

    async def _process_rpc(self, data: bytes, msg_id: int, ctx: RPCContext):
        """Process an RPC request and send the response."""
        if len(data) < 4:
            return

        # Rate limiting
        if self.user_id and not _check_rate_limit(self.user_id):
            logger.warning(f"Rate limit exceeded for user {self.user_id}")
            error_response = build_rpc_result(msg_id, build_rpc_error(420, "FLOOD_WAIT_1"))
            encrypted = encrypt_message(
                error_response, self.auth_key, self.session_id or 0,
                self.server_salt, seq_no=self.seq_no
            )
            self.seq_no += 2
            await self._send_message(encrypted)
            return

        constructor = struct.unpack_from('<I', data, 0)[0]

        # Handle message container
        if constructor == MSG_CONTAINER:
            reader_container = __import__('mtproto_server.tl_serialization', fromlist=['TLDeserializer']).TLDeserializer(data)
            reader_container.read_uint32()  # constructor
            count = reader_container.read_int32()
            for _ in range(count):
                inner_msg_id = reader_container.read_int64()
                inner_seq_no = reader_container.read_int32()
                inner_length = reader_container.read_int32()
                inner_data = reader_container.read_raw(inner_length)
                await self._process_rpc(inner_data, inner_msg_id, ctx)
            return

        # Handle msgs_ack (no response needed)
        if constructor == MSGS_ACK:
            return

        # Unwrap invokeWithLayer / initConnection
        actual_constructor, actual_data = unwrap_layers(data, ctx)

        if actual_constructor == MSGS_ACK:
            return

        # Constructors whose responses must NOT be wrapped in rpc_result
        BARE_RESPONSE_CONSTRUCTORS = {
            0x7abe77ec,  # ping
            0xf3427b8c,  # ping_delay_disconnect
            0xb921bd04,  # get_future_salts
            0xe7512126,  # destroy_session
            0x58e4a740,  # rpc_drop_answer
        }

        # Dispatch to handler
        response = dispatch_rpc(actual_constructor, actual_data if actual_data is not data else data, ctx)

        if response is None:
            return

        # Service messages are sent bare, RPC calls are wrapped in rpc_result
        if actual_constructor in BARE_RESPONSE_CONSTRUCTORS:
            result_data = response
        else:
            result_data = build_rpc_result(msg_id, response)

        # Encrypt and send
        encrypted = encrypt_message(
            result_data, self.auth_key, self.session_id or 0,
            self.server_salt, seq_no=self.seq_no
        )
        self.seq_no += 2

        await self._send_message(encrypted)


def import_time():
    import time
    return time.time()


async def start_server(host='0.0.0.0', port=443):
    """Start the MTProto TCP server."""
    db.init_db()

    # Pre-generate RSA key
    crypto.get_server_rsa_key()
    fingerprint = crypto.get_rsa_fingerprint()
    logger.info(f"Server RSA fingerprint: 0x{fingerprint & 0xFFFFFFFFFFFFFFFF:016x}")

    async def handle_client(reader, writer):
        conn = ClientConnection(reader, writer)
        await conn.handle()

    server = await asyncio.start_server(handle_client, host, port)

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    logger.info(f"MTProto server listening on {addrs}")

    async with server:
        await server.serve_forever()
