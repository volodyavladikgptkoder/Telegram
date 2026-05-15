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
            self.writer.close()
            logger.info(f"Connection closed from {self.addr}")

    async def _detect_transport(self):
        """Detect transport type from the first byte(s)."""
        first_byte = await self.reader.read(1)
        if not first_byte:
            raise ConnectionResetError()

        b = first_byte[0]
        if b == 0xef:
            self.transport_type = TRANSPORT_ABRIDGED
            logger.debug(f"{self.addr}: Using abridged transport")
        elif b == 0xee:
            # Read next 3 bytes (eeeeeeee prefix)
            rest = await self.reader.readexactly(3)
            if rest == b'\xee\xee\xee':
                self.transport_type = TRANSPORT_PADDED_INTERMEDIATE
                logger.debug(f"{self.addr}: Using padded intermediate transport")
            else:
                self.transport_type = TRANSPORT_INTERMEDIATE
                logger.debug(f"{self.addr}: Using intermediate transport")
        elif b == 0xdd:
            await self.reader.readexactly(3)
            self.transport_type = TRANSPORT_PADDED_INTERMEDIATE
        else:
            # Check for intermediate (eeeeeeee) or full transport
            rest = await self.reader.readexactly(3)
            header = first_byte + rest
            if header == b'\xee\xee\xee\xee':
                self.transport_type = TRANSPORT_INTERMEDIATE
            elif header == b'\xdd\xdd\xdd\xdd':
                self.transport_type = TRANSPORT_PADDED_INTERMEDIATE
            else:
                self.transport_type = TRANSPORT_FULL
                # The 4 bytes we read are part of the first message
                # In full transport: length(4) + seqno(4) + data + crc32(4)
                length = struct.unpack('<I', header)[0]
                remaining = await self.reader.readexactly(length - 4)
                data = remaining[4:-4]  # skip seqno, skip crc32
                await self._process_message(data)

    async def _read_message(self) -> bytes:
        """Read a single message according to the transport type."""
        try:
            if self.transport_type == TRANSPORT_ABRIDGED:
                first = await self.reader.readexactly(1)
                length = first[0]
                if length >= 0x7f:
                    length_bytes = await self.reader.readexactly(3)
                    length = struct.unpack('<I', length_bytes + b'\x00')[0]
                length *= 4
                data = await self.reader.readexactly(length)
                return data

            elif self.transport_type == TRANSPORT_INTERMEDIATE:
                length_bytes = await self.reader.readexactly(4)
                length = struct.unpack('<I', length_bytes)[0]
                data = await self.reader.readexactly(length)
                return data

            elif self.transport_type == TRANSPORT_PADDED_INTERMEDIATE:
                length_bytes = await self.reader.readexactly(4)
                length = struct.unpack('<I', length_bytes)[0]
                data = await self.reader.readexactly(length)
                return data

            elif self.transport_type == TRANSPORT_FULL:
                length_bytes = await self.reader.readexactly(4)
                length = struct.unpack('<I', length_bytes)[0]
                remaining = await self.reader.readexactly(length - 4)
                # seqno(4) + payload + crc32(4)
                data = remaining[4:-4]
                return data

        except asyncio.IncompleteReadError:
            return None

    async def _send_message(self, data: bytes):
        """Send a message according to the transport type."""
        if self.transport_type == TRANSPORT_ABRIDGED:
            length = len(data) // 4
            if length < 0x7f:
                self.writer.write(struct.pack('<B', length))
            else:
                self.writer.write(b'\x7f' + struct.pack('<I', length)[:3])
            self.writer.write(data)

        elif self.transport_type == TRANSPORT_INTERMEDIATE:
            self.writer.write(struct.pack('<I', len(data)))
            self.writer.write(data)

        elif self.transport_type == TRANSPORT_PADDED_INTERMEDIATE:
            self.writer.write(struct.pack('<I', len(data)))
            self.writer.write(data)

        elif self.transport_type == TRANSPORT_FULL:
            seqno = self.seq_no
            self.seq_no += 1
            total_len = 4 + 4 + len(data) + 4
            header = struct.pack('<II', total_len, seqno)
            body = header + data
            import binascii
            crc = binascii.crc32(body)
            self.writer.write(body + struct.pack('<I', crc))

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

        self.session_id = struct.unpack_from('<q', raw_data[24:], 8)[0] if len(raw_data) > 32 else 0

        ctx = RPCContext(
            user_id=self.user_id,
            auth_key_id=self.auth_key_id,
            session_id=self.session_id,
            layer=0
        )

        await self._process_rpc(msg.data, msg.msg_id, ctx)

        # Update user_id if changed during auth
        if ctx.user_id and ctx.user_id != self.user_id:
            self.user_id = ctx.user_id
            conn = db.get_db()
            conn.execute("UPDATE auth_keys SET user_id = ? WHERE auth_key_id = ?",
                         (self.user_id, self.auth_key_id))
            conn.commit()

    async def _process_rpc(self, data: bytes, msg_id: int, ctx: RPCContext):
        """Process an RPC request and send the response."""
        if len(data) < 4:
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

        # Dispatch to handler
        response = dispatch_rpc(actual_constructor, actual_data if actual_data is not data else data, ctx)

        if response is None:
            return

        # Wrap in rpc_result
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
