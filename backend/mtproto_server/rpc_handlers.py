"""
RPC request handlers — maps TL constructor IDs to handler functions.
Each handler reads the request, performs the operation, and returns serialized TL response.
"""

import time
import os
import random
import hashlib
import struct
import json
import logging

from mtproto_server.tl_serialization import TLSerializer, TLDeserializer
from mtproto_server import tl_constructors as C
from mtproto_server import database as db
from mtproto_server import tl_responses as R

logger = logging.getLogger(__name__)


class RPCContext:
    """Context for an RPC call — holds auth state."""
    def __init__(self, user_id=None, auth_key_id=None, session_id=None, layer=0):
        self.user_id = user_id
        self.auth_key_id = auth_key_id
        self.session_id = session_id
        self.layer = layer


def dispatch_rpc(constructor: int, data: bytes, ctx: RPCContext) -> bytes:
    """Route a TL constructor to its handler. Returns serialized response."""
    handler = HANDLERS.get(constructor)
    if handler is None:
        logger.warning(f"Unhandled constructor: 0x{constructor:08x}")
        return R.build_bool(True)
    try:
        return handler(data, ctx)
    except Exception as e:
        logger.exception(f"Error in handler 0x{constructor:08x}: {e}")
        return R.build_rpc_error_raw(500, "INTERNAL_ERROR")


def unwrap_layers(data: bytes, ctx: RPCContext) -> tuple:
    """Unwrap invokeWithLayer + initConnection wrappers, returning inner data and constructor."""
    reader = TLDeserializer(data)
    constructor = reader.read_uint32()

    if constructor == C.INVOKE_WITH_LAYER:
        ctx.layer = reader.read_int32()
        inner_data = data[reader.offset:]
        return unwrap_layers(inner_data, ctx)

    if constructor == C.INIT_CONNECTION:
        # Read initConnection fields
        flags = reader.read_int32()
        api_id = reader.read_int32()
        device_model = reader.read_string()
        system_version = reader.read_string()
        app_version = reader.read_string()
        system_lang_code = reader.read_string()
        lang_pack = reader.read_string()
        lang_code = reader.read_string()

        if flags & 1:
            proxy = reader.read_bytes()
        if flags & 2:
            params = reader.read_bytes()

        conn = db.get_db()
        conn.execute("""INSERT OR REPLACE INTO sessions 
                       (session_id, auth_key_id, user_id, layer, api_id, device_model, system_version, app_version, lang_code, system_lang_code, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                     (ctx.session_id or 0, ctx.auth_key_id or 0, ctx.user_id, ctx.layer, api_id,
                      device_model, system_version, app_version, lang_code, system_lang_code, int(time.time())))
        conn.commit()

        inner_data = data[reader.offset:]
        return unwrap_layers(inner_data, ctx)

    return constructor, data


# ============================================================
# AUTH handlers
# ============================================================

def handle_auth_send_code(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()  # constructor
    phone_number = reader.read_string()
    api_id = reader.read_int32()
    api_hash = reader.read_string()
    # settings
    settings_constructor = reader.read_uint32()
    if settings_constructor != 0xbc799737:  # if not boolFalse, skip settings
        pass

    code = str(random.randint(10000, 99999))
    phone_code_hash = hashlib.md5(f"{phone_number}:{code}:{time.time()}".encode()).hexdigest()

    conn = db.get_db()
    user = conn.execute("SELECT * FROM users WHERE phone = ?", (phone_number,)).fetchone()
    if not user:
        conn.execute("INSERT INTO users (phone, first_name, phone_code, phone_code_expires, created_at, access_hash, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (phone_number, phone_number, code, int(time.time()) + 300, int(time.time()), random.randint(1, 2**62), int(time.time())))
    else:
        conn.execute("UPDATE users SET phone_code = ?, phone_code_expires = ? WHERE phone = ?",
                     (code, int(time.time()) + 300, phone_number))
    conn.commit()

    logger.info(f"Auth code for {phone_number}: {code}")

    return R.build_auth_sent_code(phone_code_hash, len(code))


def handle_auth_resend_code(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    phone_number = reader.read_string()
    phone_code_hash = reader.read_string()

    code = str(random.randint(10000, 99999))
    conn = db.get_db()
    conn.execute("UPDATE users SET phone_code = ?, phone_code_expires = ? WHERE phone = ?",
                 (code, int(time.time()) + 300, phone_number))
    conn.commit()

    logger.info(f"Resent auth code for {phone_number}: {code}")
    return R.build_auth_sent_code(phone_code_hash, len(code))


def handle_auth_sign_in(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()
    phone_number = reader.read_string()
    phone_code_hash = reader.read_string()

    phone_code = None
    if flags & 1:
        phone_code = reader.read_string()

    conn = db.get_db()
    user = conn.execute("SELECT * FROM users WHERE phone = ?", (phone_number,)).fetchone()

    if not user:
        return R.build_rpc_error_raw(400, "PHONE_NUMBER_UNOCCUPIED")

    if not phone_code:
        return R.build_rpc_error_raw(400, "PHONE_CODE_EMPTY")

    if user['phone_code'] != phone_code:
        return R.build_rpc_error_raw(400, "PHONE_CODE_INVALID")

    # Link auth_key to user
    if ctx.auth_key_id:
        conn.execute("UPDATE auth_keys SET user_id = ? WHERE auth_key_id = ?", (user['id'], ctx.auth_key_id))

    conn.execute("UPDATE users SET is_online = 1, last_seen = ? WHERE id = ?", (int(time.time()), user['id']))
    conn.commit()

    ctx.user_id = user['id']
    return R.build_auth_authorization(user)


def handle_auth_sign_up(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()
    phone_number = reader.read_string()
    phone_code_hash = reader.read_string()
    first_name = reader.read_string()
    last_name = reader.read_string()

    conn = db.get_db()
    user = conn.execute("SELECT * FROM users WHERE phone = ?", (phone_number,)).fetchone()

    if user:
        conn.execute("UPDATE users SET first_name = ?, last_name = ? WHERE phone = ?",
                     (first_name, last_name, phone_number))
        conn.commit()
        user = conn.execute("SELECT * FROM users WHERE phone = ?", (phone_number,)).fetchone()
    else:
        conn.execute("INSERT INTO users (phone, first_name, last_name, created_at, access_hash, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
                     (phone_number, first_name, last_name, int(time.time()), random.randint(1, 2**62), int(time.time())))
        conn.commit()
        user = conn.execute("SELECT * FROM users WHERE phone = ?", (phone_number,)).fetchone()

    if ctx.auth_key_id:
        conn.execute("UPDATE auth_keys SET user_id = ? WHERE auth_key_id = ?", (user['id'], ctx.auth_key_id))
        conn.commit()

    ctx.user_id = user['id']
    return R.build_auth_authorization(user)


def handle_auth_log_out(data: bytes, ctx: RPCContext) -> bytes:
    if ctx.user_id:
        conn = db.get_db()
        conn.execute("UPDATE users SET is_online = 0, last_seen = ? WHERE id = ?", (int(time.time()), ctx.user_id))
        conn.commit()
    return R.build_auth_logged_out()


def handle_auth_export_authorization(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_auth_exported_authorization(ctx.user_id or 0)


def handle_auth_import_authorization(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    user_id = reader.read_int64()
    auth_bytes = reader.read_bytes()

    conn = db.get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user:
        ctx.user_id = user_id
        return R.build_auth_authorization(user)
    return R.build_rpc_error_raw(400, "USER_ID_INVALID")


def handle_auth_bind_temp(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)


def handle_auth_check_password(data: bytes, ctx: RPCContext) -> bytes:
    conn = db.get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (ctx.user_id,)).fetchone()
    if user:
        return R.build_auth_authorization(user)
    return R.build_rpc_error_raw(400, "USER_ID_INVALID")


# ============================================================
# USERS handlers
# ============================================================

def handle_users_get_users(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    # vector of InputUser
    vector_constructor = reader.read_uint32()
    count = reader.read_int32()

    users = []
    conn = db.get_db()
    for _ in range(count):
        input_constructor = reader.read_uint32()
        if input_constructor == 0xb98886cf:  # inputUserSelf
            if ctx.user_id:
                user = conn.execute("SELECT * FROM users WHERE id = ?", (ctx.user_id,)).fetchone()
                if user:
                    users.append(user)
        elif input_constructor == 0xf21158c6:  # inputUser
            user_id = reader.read_int64()
            access_hash = reader.read_int64()
            user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if user:
                users.append(user)
        elif input_constructor == 0xd8292816:  # inputUserEmpty
            pass

    return R.build_vector_users(users)


def handle_users_get_full_user(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    input_constructor = reader.read_uint32()

    conn = db.get_db()
    user_id = ctx.user_id

    if input_constructor == 0xb98886cf:  # inputUserSelf
        user_id = ctx.user_id
    elif input_constructor == 0xf21158c6:  # inputUser
        user_id = reader.read_int64()
        access_hash = reader.read_int64()

    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return R.build_rpc_error_raw(400, "USER_ID_INVALID")

    return R.build_user_full(user)


# ============================================================
# ACCOUNT handlers
# ============================================================

def handle_account_update_profile(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()

    conn = db.get_db()
    updates = {}
    if flags & 1:
        updates['first_name'] = reader.read_string()
    if flags & 2:
        updates['last_name'] = reader.read_string()
    if flags & 4:
        updates['bio'] = reader.read_string()

    if updates and ctx.user_id:
        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        conn.execute(f"UPDATE users SET {set_clause} WHERE id = ?", (*updates.values(), ctx.user_id))
        conn.commit()

    user = conn.execute("SELECT * FROM users WHERE id = ?", (ctx.user_id,)).fetchone()
    return R.build_user(user)


def handle_account_update_status(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    offline = reader.read_bool()

    if ctx.user_id:
        conn = db.get_db()
        conn.execute("UPDATE users SET is_online = ?, last_seen = ? WHERE id = ?",
                     (0 if offline else 1, int(time.time()), ctx.user_id))
        conn.commit()

    return R.build_bool(True)


def handle_account_update_username(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    username = reader.read_string()

    if ctx.user_id:
        conn = db.get_db()
        existing = conn.execute("SELECT id FROM users WHERE username = ? AND id != ?", (username, ctx.user_id)).fetchone()
        if existing:
            return R.build_rpc_error_raw(400, "USERNAME_OCCUPIED")
        conn.execute("UPDATE users SET username = ? WHERE id = ?", (username, ctx.user_id))
        conn.commit()

    user = db.get_db().execute("SELECT * FROM users WHERE id = ?", (ctx.user_id,)).fetchone()
    return R.build_user(user)


def handle_account_get_password(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_account_password(has_password=False)


def handle_account_register_device(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)


def handle_account_unregister_device(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)


def handle_account_get_authorizations(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_account_authorizations(ctx)


def handle_account_get_privacy(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_account_privacy_rules()


def handle_account_set_privacy(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_account_privacy_rules()


def handle_account_get_wall_papers(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_wall_papers()


# ============================================================
# CONTACTS handlers
# ============================================================

def handle_contacts_get_contacts(data: bytes, ctx: RPCContext) -> bytes:
    conn = db.get_db()
    contacts = conn.execute("""
        SELECT u.* FROM contacts c 
        JOIN users u ON c.contact_user_id = u.id 
        WHERE c.user_id = ? AND c.is_blocked = 0
    """, (ctx.user_id,)).fetchall()
    return R.build_contacts(contacts, ctx.user_id)


def handle_contacts_import_contacts(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    vector_constructor = reader.read_uint32()
    count = reader.read_int32()

    conn = db.get_db()
    imported = []
    users = []

    for _ in range(count):
        contact_constructor = reader.read_uint32()
        phone = reader.read_string()
        first_name = reader.read_string()
        last_name = reader.read_string()

        user = conn.execute("SELECT * FROM users WHERE phone = ?", (phone,)).fetchone()
        if user:
            try:
                conn.execute("INSERT OR IGNORE INTO contacts (user_id, contact_user_id, is_mutual, added_at) VALUES (?, ?, 0, ?)",
                             (ctx.user_id, user['id'], int(time.time())))
                imported.append(user['id'])
                users.append(user)
            except Exception:
                pass

    conn.commit()
    return R.build_contacts_imported(imported, users)


def handle_contacts_delete_contacts(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_contacts_get_blocked(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_contacts_blocked()


def handle_contacts_block(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)


def handle_contacts_unblock(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)


def handle_contacts_search(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    q = reader.read_string()
    limit = reader.read_int32()

    conn = db.get_db()
    users = conn.execute("SELECT * FROM users WHERE username LIKE ? OR first_name LIKE ? OR phone LIKE ? LIMIT ?",
                         (f"%{q}%", f"%{q}%", f"%{q}%", limit)).fetchall()
    return R.build_contacts_found(users)


def handle_contacts_resolve_username(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    username = reader.read_string()

    conn = db.get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user:
        return R.build_contacts_resolved_peer(user=user)

    chat = conn.execute("SELECT * FROM chats WHERE username = ?", (username,)).fetchone()
    if chat:
        return R.build_contacts_resolved_peer(chat=chat)

    return R.build_rpc_error_raw(400, "USERNAME_NOT_OCCUPIED")


# ============================================================
# MESSAGES handlers
# ============================================================

def handle_messages_get_dialogs(data: bytes, ctx: RPCContext) -> bytes:
    conn = db.get_db()
    dialogs = conn.execute("SELECT * FROM dialogs WHERE user_id = ? ORDER BY top_message_id DESC LIMIT 100",
                           (ctx.user_id,)).fetchall()

    messages = []
    users = []
    chats = []
    user_ids = set()
    chat_ids = set()

    for d in dialogs:
        if d['top_message_id']:
            msg = conn.execute("SELECT * FROM messages WHERE id = ?", (d['top_message_id'],)).fetchone()
            if msg:
                messages.append(msg)
                user_ids.add(msg['sender_id'])
        if d['peer_type'] == 'user':
            user_ids.add(d['peer_id'])
        else:
            chat_ids.add(d['peer_id'])

    for uid in user_ids:
        u = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if u:
            users.append(u)

    for cid in chat_ids:
        c = conn.execute("SELECT * FROM chats WHERE id = ?", (cid,)).fetchone()
        if c:
            chats.append(c)

    return R.build_messages_dialogs(dialogs, messages, users, chats)


def handle_messages_get_history(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    peer_constructor = reader.read_uint32()

    peer_id = 0
    if peer_constructor == 0x7b8e7de6:  # inputPeerUser
        peer_id = reader.read_int64()
        access_hash = reader.read_int64()
    elif peer_constructor == 0x35a95cb9:  # inputPeerChat
        peer_id = reader.read_int64()
    elif peer_constructor == 0xa87b0a1c:  # inputPeerChannel
        peer_id = reader.read_int64()
        access_hash = reader.read_int64()
    elif peer_constructor == 0x7da07ec9:  # inputPeerSelf
        peer_id = ctx.user_id

    offset_id = reader.read_int32()
    offset_date = reader.read_int32()
    add_offset = reader.read_int32()
    limit = reader.read_int32()
    max_id = reader.read_int32()
    min_id = reader.read_int32()
    msg_hash = reader.read_int64()

    conn = db.get_db()

    # Find chat between the two users or the group/channel
    chat = conn.execute("SELECT * FROM chats WHERE id = ?", (peer_id,)).fetchone()
    chat_id = peer_id

    if not chat:
        # Private chat — find or create
        chat_id = _get_or_create_private_chat(ctx.user_id, peer_id)

    query = "SELECT * FROM messages WHERE chat_id = ? AND is_deleted = 0"
    params = [chat_id]

    if offset_id > 0:
        query += " AND id < ?"
        params.append(offset_id)

    query += " ORDER BY date DESC LIMIT ?"
    params.append(min(limit, 100))

    messages = conn.execute(query, params).fetchall()

    user_ids = set()
    for msg in messages:
        user_ids.add(msg['sender_id'])

    users = []
    for uid in user_ids:
        u = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if u:
            users.append(u)

    return R.build_messages_messages(messages, users, [])


def handle_messages_send_message(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()

    peer_constructor = reader.read_uint32()
    peer_id = 0
    if peer_constructor == 0x7b8e7de6:  # inputPeerUser
        peer_id = reader.read_int64()
        access_hash = reader.read_int64()
    elif peer_constructor == 0x35a95cb9:  # inputPeerChat
        peer_id = reader.read_int64()
    elif peer_constructor == 0xa87b0a1c:  # inputPeerChannel
        peer_id = reader.read_int64()
        access_hash = reader.read_int64()
    elif peer_constructor == 0x7da07ec9:  # inputPeerSelf
        peer_id = ctx.user_id

    reply_to_id = None
    if flags & 1:
        reply_constructor = reader.read_uint32()
        if reply_constructor == 0x73ec805:  # inputReplyToMessage
            reply_flags = reader.read_int32()
            reply_to_id = reader.read_int32()

    message_text = reader.read_string()
    random_id = reader.read_int64()

    conn = db.get_db()

    chat = conn.execute("SELECT * FROM chats WHERE id = ?", (peer_id,)).fetchone()
    chat_id = peer_id
    if not chat:
        chat_id = _get_or_create_private_chat(ctx.user_id, peer_id)

    pts = db.get_next_pts(ctx.user_id)

    conn.execute("""INSERT INTO messages (chat_id, sender_id, text, reply_to_id, date, message_type, is_outgoing, pts)
                    VALUES (?, ?, ?, ?, ?, 'text', 1, ?)""",
                 (chat_id, ctx.user_id, message_text, reply_to_id, int(time.time()), pts))
    msg_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    # Update dialog
    conn.execute("""INSERT OR REPLACE INTO dialogs (user_id, peer_type, peer_id, top_message_id, pts)
                    VALUES (?, ?, ?, ?, ?)""",
                 (ctx.user_id, 'user' if not chat else chat['chat_type'], peer_id, msg_id, pts))

    if peer_id != ctx.user_id:
        conn.execute("""INSERT OR REPLACE INTO dialogs (user_id, peer_type, peer_id, top_message_id, unread_count, pts)
                        VALUES (?, ?, ?, ?, COALESCE((SELECT unread_count FROM dialogs WHERE user_id = ? AND peer_id = ?), 0) + 1, ?)""",
                     (peer_id, 'user', ctx.user_id, msg_id, peer_id, ctx.user_id, pts))

    conn.commit()

    msg = conn.execute("SELECT * FROM messages WHERE id = ?", (msg_id,)).fetchone()

    # Real-time push: notify the recipient
    if peer_id != ctx.user_id:
        sender = conn.execute("SELECT * FROM users WHERE id = ?", (ctx.user_id,)).fetchone()
        from mtproto_server.tcp_server import push_update_to_user
        push_update_to_user(peer_id, R.build_update_new_message(msg, pts, [sender] if sender else []))

    return R.build_updates_short_sent_message(msg, pts)


def handle_messages_send_media(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()

    peer_constructor = reader.read_uint32()
    peer_id = 0
    if peer_constructor == 0x7b8e7de6:
        peer_id = reader.read_int64()
        reader.read_int64()
    elif peer_constructor == 0x35a95cb9:
        peer_id = reader.read_int64()
    elif peer_constructor == 0xa87b0a1c:
        peer_id = reader.read_int64()
        reader.read_int64()

    conn = db.get_db()
    chat_id = peer_id
    chat = conn.execute("SELECT * FROM chats WHERE id = ?", (peer_id,)).fetchone()
    if not chat:
        chat_id = _get_or_create_private_chat(ctx.user_id, peer_id)

    pts = db.get_next_pts(ctx.user_id)

    conn.execute("""INSERT INTO messages (chat_id, sender_id, text, date, message_type, is_outgoing, pts)
                    VALUES (?, ?, '', ?, 'media', 1, ?)""",
                 (chat_id, ctx.user_id, int(time.time()), pts))
    msg_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit()

    msg = conn.execute("SELECT * FROM messages WHERE id = ?", (msg_id,)).fetchone()
    return R.build_updates_short_sent_message(msg, pts)


def handle_messages_edit_message(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()

    peer_constructor = reader.read_uint32()
    peer_id = 0
    if peer_constructor in (0x7b8e7de6, 0xa87b0a1c):
        peer_id = reader.read_int64()
        reader.read_int64()
    elif peer_constructor == 0x35a95cb9:
        peer_id = reader.read_int64()

    msg_id = reader.read_int32()

    new_text = None
    if flags & (1 << 11):
        new_text = reader.read_string()

    if new_text and ctx.user_id:
        conn = db.get_db()
        conn.execute("UPDATE messages SET text = ?, edit_date = ? WHERE id = ? AND sender_id = ?",
                     (new_text, int(time.time()), msg_id, ctx.user_id))
        conn.commit()

    return R.build_updates_empty()


def handle_messages_delete_messages(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()

    vector_constructor = reader.read_uint32()
    count = reader.read_int32()
    msg_ids = [reader.read_int32() for _ in range(count)]

    conn = db.get_db()
    pts = db.get_next_pts(ctx.user_id)
    for mid in msg_ids:
        conn.execute("UPDATE messages SET is_deleted = 1 WHERE id = ?", (mid,))
    conn.commit()

    return R.build_affected_messages(pts, len(msg_ids))


def handle_messages_forward_messages(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_messages_read_history(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()

    peer_constructor = reader.read_uint32()
    peer_id = 0
    if peer_constructor in (0x7b8e7de6, 0xa87b0a1c):
        peer_id = reader.read_int64()
        reader.read_int64()
    elif peer_constructor == 0x35a95cb9:
        peer_id = reader.read_int64()

    max_id = reader.read_int32()

    conn = db.get_db()
    pts = db.get_next_pts(ctx.user_id)
    conn.execute("UPDATE dialogs SET read_inbox_max_id = ?, unread_count = 0 WHERE user_id = ? AND peer_id = ?",
                 (max_id, ctx.user_id, peer_id))
    conn.commit()

    return R.build_affected_messages(pts, 0)


def handle_messages_set_typing(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    peer_constructor = reader.read_uint32()
    peer_id = 0
    if peer_constructor == 0x7b8e7de6:
        peer_id = reader.read_int64()
        reader.read_int64()
    elif peer_constructor == 0x35a95cb9:
        peer_id = reader.read_int64()
    elif peer_constructor == 0xa87b0a1c:
        peer_id = reader.read_int64()
        reader.read_int64()

    # Push typing indicator to peer
    if peer_id and ctx.user_id and peer_id != ctx.user_id:
        from mtproto_server.tcp_server import push_update_to_user
        push_update_to_user(peer_id, R.build_update_user_typing(ctx.user_id, peer_id))

    return R.build_bool(True)


def handle_messages_search(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_messages_messages([], [], [])


def handle_messages_received_messages(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_vector_received_messages()


def handle_messages_get_peer_dialogs(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_peer_dialogs()


def handle_messages_send_reaction(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_messages_get_messages_reactions(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_messages_get_messages(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_messages_messages([], [], [])


def handle_messages_update_pinned_message(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_messages_get_pinned_messages(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_messages_messages([], [], [])


def handle_messages_set_chat_wall_paper(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


# ============================================================
# CHAT/GROUP handlers
# ============================================================

def handle_messages_create_chat(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()

    vector_constructor = reader.read_uint32()
    count = reader.read_int32()
    user_ids = []
    for _ in range(count):
        input_constructor = reader.read_uint32()
        uid = reader.read_int64()
        access_hash = reader.read_int64()
        user_ids.append(uid)

    title = reader.read_string()

    conn = db.get_db()
    conn.execute("INSERT INTO chats (chat_type, title, creator_id, member_count, access_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                 ('group', title, ctx.user_id, len(user_ids) + 1, random.randint(1, 2**62), int(time.time())))
    chat_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    conn.execute("INSERT INTO chat_members (chat_id, user_id, role, joined_at) VALUES (?, ?, 'creator', ?)",
                 (chat_id, ctx.user_id, int(time.time())))
    for uid in user_ids:
        conn.execute("INSERT OR IGNORE INTO chat_members (chat_id, user_id, role, joined_at) VALUES (?, ?, 'member', ?)",
                     (chat_id, uid, int(time.time())))
    conn.commit()

    return R.build_updates_empty()


def handle_messages_get_full_chat(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    chat_id = reader.read_int64()

    conn = db.get_db()
    chat = conn.execute("SELECT * FROM chats WHERE id = ?", (chat_id,)).fetchone()
    if not chat:
        return R.build_rpc_error_raw(400, "CHAT_ID_INVALID")

    members = conn.execute("SELECT * FROM chat_members WHERE chat_id = ?", (chat_id,)).fetchall()
    users = []
    for m in members:
        u = conn.execute("SELECT * FROM users WHERE id = ?", (m['user_id'],)).fetchone()
        if u:
            users.append(u)

    return R.build_messages_chat_full(chat, members, users)


def handle_messages_edit_chat_title(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    chat_id = reader.read_int64()
    title = reader.read_string()

    conn = db.get_db()
    conn.execute("UPDATE chats SET title = ? WHERE id = ?", (title, chat_id))
    conn.commit()
    return R.build_updates_empty()


def handle_messages_edit_chat_photo(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_messages_add_chat_user(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_messages_delete_chat_user(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


# ============================================================
# CHANNEL handlers
# ============================================================

def handle_channels_create(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()
    title = reader.read_string()
    about = reader.read_string()

    is_channel = not (flags & 1)  # megagroup flag
    chat_type = 'channel' if is_channel else 'supergroup'

    conn = db.get_db()
    conn.execute("INSERT INTO chats (chat_type, title, description, creator_id, member_count, access_hash, created_at) VALUES (?, ?, ?, ?, 1, ?, ?)",
                 (chat_type, title, about, ctx.user_id, random.randint(1, 2**62), int(time.time())))
    chat_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO chat_members (chat_id, user_id, role, joined_at) VALUES (?, ?, 'creator', ?)",
                 (chat_id, ctx.user_id, int(time.time())))
    conn.commit()
    return R.build_updates_empty()


def handle_channels_get_channels(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_messages_chats([])


def handle_channels_get_full_channel(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_messages_chat_full_empty()


def handle_channels_join(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_channels_leave(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_channels_edit_title(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_channels_edit_about(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)


def handle_channels_edit_photo(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_channels_invite(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_channels_delete(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_channels_edit_admin(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_channels_edit_banned(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_channels_get_participants(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_channels_participants()


# ============================================================
# UPLOAD handlers
# ============================================================

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)


def _get_file_path(file_id: int) -> str:
    """Get filesystem path for a file's parts directory."""
    dir_path = os.path.join(UPLOAD_DIR, str(file_id))
    os.makedirs(dir_path, exist_ok=True)
    return dir_path


def handle_upload_save_file_part(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    file_id = reader.read_int64()
    file_part = reader.read_int32()
    file_bytes = reader.read_bytes()

    dir_path = _get_file_path(file_id)
    part_path = os.path.join(dir_path, f"part_{file_part:06d}")
    with open(part_path, 'wb') as f:
        f.write(file_bytes)

    logger.info(f"Saved file part {file_part} for file {file_id}, size={len(file_bytes)}")
    return R.build_bool(True)


def handle_upload_save_big_file_part(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    file_id = reader.read_int64()
    file_part = reader.read_int32()
    file_total_parts = reader.read_int32()
    file_bytes = reader.read_bytes()

    dir_path = _get_file_path(file_id)
    part_path = os.path.join(dir_path, f"part_{file_part:06d}")
    with open(part_path, 'wb') as f:
        f.write(file_bytes)

    # Track total parts for assembly
    meta_path = os.path.join(dir_path, "meta.json")
    import json as _json
    meta = {"total_parts": file_total_parts, "file_id": file_id}
    with open(meta_path, 'w') as f:
        _json.dump(meta, f)

    logger.info(f"Saved big file part {file_part}/{file_total_parts} for file {file_id}, size={len(file_bytes)}")
    return R.build_bool(True)


def handle_upload_get_file(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()
    location_constructor = reader.read_uint32()

    # Try to read file from filesystem
    # For now, return empty — actual file retrieval requires tracking file_id from location
    return R.build_upload_file(b'', 'application/octet-stream')


# ============================================================
# UPDATES handlers
# ============================================================

def handle_updates_get_state(data: bytes, ctx: RPCContext) -> bytes:
    conn = db.get_db()
    state = conn.execute("SELECT * FROM updates_state WHERE user_id = ?", (ctx.user_id,)).fetchone()
    pts = state['pts'] if state else 0
    qts = state['qts'] if state else 0
    date = state['date'] if state else int(time.time())
    seq = state['seq'] if state else 0
    return R.build_updates_state(pts, qts, date, seq)


def handle_updates_get_difference(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_difference_empty()


def handle_updates_get_channel_difference(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_channel_difference_empty()


# ============================================================
# HELP handlers
# ============================================================

def handle_help_get_config(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_config()


def handle_help_get_nearest_dc(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_nearest_dc()


def handle_help_get_app_update(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_no_app_update()


def handle_help_get_cdn_config(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_cdn_config()


def handle_help_get_app_config(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_app_config()


def handle_help_get_terms_of_service(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_terms_of_service()


def handle_help_get_countries_list(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_countries_list()


# ============================================================
# STICKERS handlers
# ============================================================

def handle_get_all_stickers(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_all_stickers()


def handle_get_sticker_set(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_sticker_set()


def handle_install_sticker_set(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_sticker_set_installed()


def handle_get_recent_stickers(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_recent_stickers()


def handle_save_recent_sticker(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)


def handle_get_faved_stickers(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_faved_stickers()


def handle_fave_sticker(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)


# ============================================================
# POLLS handlers
# ============================================================

def handle_send_vote(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_get_poll_results(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_get_poll_votes(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_poll_votes()


# ============================================================
# PHOTOS handlers
# ============================================================

def handle_photos_update_profile_photo(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_photos_photo()


def handle_photos_upload_profile_photo(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_photos_photo()


# ============================================================
# STORIES handlers
# ============================================================

def handle_stories_get_all(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_stories_all()


def handle_stories_get_peer(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_stories_peer()


def handle_stories_send(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_stories_delete(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_stories_get_views(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_stories_views()


def handle_stories_read(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


# ============================================================
# LANGPACK handlers
# ============================================================

def handle_langpack_get_languages(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_langpack_languages()


def handle_langpack_get_lang_pack(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_langpack_difference()


def handle_langpack_get_strings(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_langpack_strings()


def handle_langpack_get_difference(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_langpack_difference()


# ============================================================
# SERVICE handlers
# ============================================================

def handle_ping(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    ping_id = reader.read_int64()
    return R.build_pong(ping_id)


def handle_ping_delay_disconnect(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    ping_id = reader.read_int64()
    disconnect_delay = reader.read_int32()
    return R.build_pong(ping_id)


def handle_msgs_ack(data: bytes, ctx: RPCContext) -> bytes:
    return None  # No response needed


def handle_destroy_session(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    session_id = reader.read_int64()
    return R.build_destroy_session_ok(session_id)


def handle_get_future_salts(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    num = reader.read_int32()
    return R.build_future_salts(num)


def handle_rpc_drop_answer(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_rpc_answer_dropped()


# ============================================================
# Helper functions
# ============================================================

def _get_or_create_private_chat(user1_id: int, user2_id: int) -> int:
    """Get or create a private chat between two users."""
    conn = db.get_db()
    min_id = min(user1_id, user2_id)
    max_id = max(user1_id, user2_id)

    chat = conn.execute("""
        SELECT c.id FROM chats c
        JOIN chat_members cm1 ON c.id = cm1.chat_id AND cm1.user_id = ?
        JOIN chat_members cm2 ON c.id = cm2.chat_id AND cm2.user_id = ?
        WHERE c.chat_type = 'private'
    """, (min_id, max_id)).fetchone()

    if chat:
        return chat['id']

    conn.execute("INSERT INTO chats (chat_type, member_count, access_hash, created_at) VALUES ('private', 2, ?, ?)",
                 (random.randint(1, 2**62), int(time.time())))
    chat_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO chat_members (chat_id, user_id, role, joined_at) VALUES (?, ?, 'member', ?)",
                 (chat_id, user1_id, int(time.time())))
    conn.execute("INSERT INTO chat_members (chat_id, user_id, role, joined_at) VALUES (?, ?, 'member', ?)",
                 (chat_id, user2_id, int(time.time())))
    conn.commit()
    return chat_id


# ============================================================
# VoIP / Phone Call handlers
# ============================================================

def handle_phone_request_call(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()  # constructor
    flags = reader.read_int32()
    # inputUser
    input_constructor = reader.read_uint32()
    user_id = reader.read_int64()
    access_hash = reader.read_int64()
    random_id = reader.read_int32()
    g_a_hash = reader.read_bytes()

    conn = db.get_db()
    call_access_hash = random.randint(1, 2**62)
    conn.execute("""INSERT INTO phone_calls (access_hash, caller_id, callee_id, g_a_hash, is_video, state, created_at)
                    VALUES (?, ?, ?, ?, ?, 'requested', ?)""",
                 (call_access_hash, ctx.user_id, user_id, g_a_hash, 1 if (flags & 1) else 0, int(time.time())))
    call_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit()

    call = conn.execute("SELECT * FROM phone_calls WHERE id = ?", (call_id,)).fetchone()
    users = []
    for uid in (ctx.user_id, user_id):
        u = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if u:
            users.append(u)

    # Push update to callee
    from mtproto_server.tcp_server import push_update_to_user
    push_update_to_user(user_id, R.build_phone_call(call, users))

    return R.build_phone_call(call, users)


def handle_phone_accept_call(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    # inputPhoneCall
    peer_constructor = reader.read_uint32()
    call_id = reader.read_int64()
    access_hash = reader.read_int64()
    g_b = reader.read_bytes()

    conn = db.get_db()
    conn.execute("UPDATE phone_calls SET g_b = ?, state = 'accepted' WHERE id = ?", (g_b, call_id))
    conn.commit()
    call = conn.execute("SELECT * FROM phone_calls WHERE id = ?", (call_id,)).fetchone()
    if not call:
        return R.build_rpc_error_raw(400, "CALL_PEER_INVALID")

    users = []
    for uid in (call['caller_id'], call['callee_id']):
        u = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if u:
            users.append(u)
    return R.build_phone_call(call, users)


def handle_phone_confirm_call(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    peer_constructor = reader.read_uint32()
    call_id = reader.read_int64()
    access_hash = reader.read_int64()
    g_a = reader.read_bytes()
    key_fingerprint = reader.read_int64()

    conn = db.get_db()
    conn.execute("UPDATE phone_calls SET g_a = ?, state = 'confirmed' WHERE id = ?", (g_a, call_id))
    conn.commit()
    call = conn.execute("SELECT * FROM phone_calls WHERE id = ?", (call_id,)).fetchone()
    if not call:
        return R.build_rpc_error_raw(400, "CALL_PEER_INVALID")
    users = []
    for uid in (call['caller_id'], call['callee_id']):
        u = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if u:
            users.append(u)
    return R.build_phone_call(call, users)


def handle_phone_discard_call(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()
    peer_constructor = reader.read_uint32()
    call_id = reader.read_int64()
    access_hash = reader.read_int64()
    duration = reader.read_int32()
    reason_constructor = reader.read_uint32()

    conn = db.get_db()
    conn.execute("UPDATE phone_calls SET state = 'discarded', duration = ? WHERE id = ?", (duration, call_id))
    conn.commit()
    return R.build_updates_empty()


def handle_phone_received_call(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    peer_constructor = reader.read_uint32()
    call_id = reader.read_int64()
    access_hash = reader.read_int64()

    conn = db.get_db()
    conn.execute("UPDATE phone_calls SET state = 'received' WHERE id = ?", (call_id,))
    conn.commit()
    return R.build_bool(True)


def handle_phone_set_call_rating(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()
    peer_constructor = reader.read_uint32()
    call_id = reader.read_int64()
    access_hash = reader.read_int64()
    rating = reader.read_int32()
    comment = reader.read_string()

    conn = db.get_db()
    conn.execute("UPDATE phone_calls SET rating = ?, comment = ? WHERE id = ?", (rating, comment, call_id))
    conn.commit()
    return R.build_updates_empty()


def handle_phone_save_call_debug(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)


# ============================================================
# Secret Chat handlers
# ============================================================

def handle_messages_get_dh_config(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_messages_dh_config(os.urandom(256))


def handle_messages_request_encryption(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    input_constructor = reader.read_uint32()
    user_id = reader.read_int64()
    access_hash = reader.read_int64()
    random_id = reader.read_int32()
    g_a = reader.read_bytes()

    conn = db.get_db()
    chat_access_hash = random.randint(1, 2**62)
    conn.execute("""INSERT INTO encrypted_chats (access_hash, creator_id, participant_id, g_a, state, created_at)
                    VALUES (?, ?, ?, ?, 'requested', ?)""",
                 (chat_access_hash, ctx.user_id, user_id, g_a, int(time.time())))
    chat_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit()

    chat = conn.execute("SELECT * FROM encrypted_chats WHERE id = ?", (chat_id,)).fetchone()
    return R.build_encrypted_chat_requested(chat)


def handle_messages_accept_encryption(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    # inputEncryptedChat
    chat_id = reader.read_int32()
    access_hash = reader.read_int64()
    g_b = reader.read_bytes()
    key_fingerprint = reader.read_int64()

    conn = db.get_db()
    conn.execute("UPDATE encrypted_chats SET g_b = ?, key_fingerprint = ?, state = 'accepted' WHERE id = ?",
                 (g_b, key_fingerprint, chat_id))
    conn.commit()

    chat = conn.execute("SELECT * FROM encrypted_chats WHERE id = ?", (chat_id,)).fetchone()
    if not chat:
        return R.build_rpc_error_raw(400, "CHAT_ID_INVALID")
    return R.build_encrypted_chat(chat)


def handle_messages_discard_encryption(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()
    chat_id = reader.read_int32()

    conn = db.get_db()
    conn.execute("UPDATE encrypted_chats SET state = 'discarded' WHERE id = ?", (chat_id,))
    conn.commit()
    return R.build_bool(True)


def handle_messages_send_encrypted(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_messages_sent_encrypted_message()


def handle_messages_send_encrypted_file(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_messages_sent_encrypted_message()


def handle_messages_send_encrypted_service(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_messages_sent_encrypted_message()


def handle_messages_read_encrypted_history(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)


# ============================================================
# Bot handlers
# ============================================================

def handle_messages_get_bot_callback_answer(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bot_callback_answer()


def handle_messages_set_bot_callback_answer(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)


def handle_messages_get_inline_bot_results(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bot_results_empty()


def handle_messages_send_inline_bot_result(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_messages_set_bot_commands(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)


def handle_messages_get_bot_commands(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x1cb5c415)  # vector
    s.write_int32(0)
    return s.get_bytes()


# ============================================================
# Drafts handlers
# ============================================================

def handle_messages_save_draft(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()

    reply_to_msg_id = None
    if flags & 1:
        reply_constructor = reader.read_uint32()
        if reply_constructor == 0x73ec805:
            rf = reader.read_int32()
            reply_to_msg_id = reader.read_int32()

    peer_constructor = reader.read_uint32()
    peer_id = 0
    peer_type = 'user'
    if peer_constructor == 0x7b8e7de6:
        peer_id = reader.read_int64()
        reader.read_int64()
    elif peer_constructor == 0x35a95cb9:
        peer_id = reader.read_int64()
        peer_type = 'chat'
    elif peer_constructor == 0xa87b0a1c:
        peer_id = reader.read_int64()
        reader.read_int64()
        peer_type = 'channel'

    message = reader.read_string()

    conn = db.get_db()
    conn.execute("""INSERT OR REPLACE INTO drafts (user_id, peer_type, peer_id, message, reply_to_msg_id, date)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                 (ctx.user_id, peer_type, peer_id, message, reply_to_msg_id, int(time.time())))
    conn.commit()
    return R.build_bool(True)


def handle_messages_get_all_drafts(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_messages_clear_all_drafts(data: bytes, ctx: RPCContext) -> bytes:
    conn = db.get_db()
    conn.execute("DELETE FROM drafts WHERE user_id = ?", (ctx.user_id,))
    conn.commit()
    return R.build_bool(True)


# ============================================================
# Dialog Filters handlers
# ============================================================

def handle_messages_get_dialog_filters(data: bytes, ctx: RPCContext) -> bytes:
    conn = db.get_db()
    filters = conn.execute("SELECT * FROM dialog_filters WHERE user_id = ? ORDER BY order_pos",
                           (ctx.user_id,)).fetchall()
    return R.build_dialog_filters(filters)


def handle_messages_update_dialog_filter(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()
    filter_id = reader.read_int32()

    conn = db.get_db()
    if flags & 1:
        # Update / create filter
        filter_constructor = reader.read_uint32()
        f_flags = reader.read_int32()
        f_id = reader.read_int32()
        title = reader.read_string()

        conn.execute("""INSERT OR REPLACE INTO dialog_filters (id, user_id, title, flags)
                        VALUES (?, ?, ?, ?)""", (filter_id, ctx.user_id, title, f_flags))
    else:
        conn.execute("DELETE FROM dialog_filters WHERE id = ? AND user_id = ?", (filter_id, ctx.user_id))
    conn.commit()
    return R.build_bool(True)


def handle_messages_update_dialog_filters_order(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)


def handle_messages_get_dialog_unread_marks(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_dialog_unread_marks()


def handle_messages_mark_dialog_unread(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)


# ============================================================
# Scheduled Messages handlers
# ============================================================

def handle_messages_get_scheduled_history(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    peer_constructor = reader.read_uint32()
    peer_id = 0
    if peer_constructor in (0x7b8e7de6, 0xa87b0a1c):
        peer_id = reader.read_int64()
        reader.read_int64()
    elif peer_constructor == 0x35a95cb9:
        peer_id = reader.read_int64()

    conn = db.get_db()
    chat_id = peer_id
    msgs = conn.execute("SELECT * FROM scheduled_messages WHERE chat_id = ? AND sender_id = ? AND is_sent = 0 ORDER BY schedule_date",
                        (chat_id, ctx.user_id)).fetchall()

    # Convert to message-like format for response
    message_rows = []
    for m in msgs:
        message_rows.append({
            'id': m['id'],
            'chat_id': m['chat_id'],
            'sender_id': m['sender_id'],
            'text': m['text'] or '',
            'date': m['schedule_date'],
            'reply_to_id': m['reply_to_id'],
            'edit_date': None,
            'entities_json': m['entities_json'],
            'is_pinned': 0,
            'is_outgoing': 1,
            'is_deleted': 0,
            'views': 0,
            'message_type': 'text',
            'media_json': None,
            'pts': 0,
            'forward_from_id': None,
            'forward_from_chat_id': None,
            'forward_from_message_id': None,
            'group_id': None,
        })

    return R.build_messages_messages(message_rows, [], [])


def handle_messages_get_scheduled_messages(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_messages_messages([], [], [])


def handle_messages_send_scheduled_messages(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    peer_constructor = reader.read_uint32()
    peer_id = 0
    if peer_constructor in (0x7b8e7de6, 0xa87b0a1c):
        peer_id = reader.read_int64()
        reader.read_int64()
    elif peer_constructor == 0x35a95cb9:
        peer_id = reader.read_int64()

    vector_constructor = reader.read_uint32()
    count = reader.read_int32()
    msg_ids = [reader.read_int32() for _ in range(count)]

    conn = db.get_db()
    for mid in msg_ids:
        scheduled = conn.execute("SELECT * FROM scheduled_messages WHERE id = ? AND sender_id = ?",
                                 (mid, ctx.user_id)).fetchone()
        if scheduled:
            pts = db.get_next_pts(ctx.user_id)
            conn.execute("""INSERT INTO messages (chat_id, sender_id, text, date, message_type, is_outgoing, pts)
                            VALUES (?, ?, ?, ?, 'text', 1, ?)""",
                         (scheduled['chat_id'], ctx.user_id, scheduled['text'], int(time.time()), pts))
            conn.execute("UPDATE scheduled_messages SET is_sent = 1 WHERE id = ?", (mid,))
    conn.commit()
    return R.build_updates_empty()


def handle_messages_delete_scheduled_messages(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    peer_constructor = reader.read_uint32()
    if peer_constructor in (0x7b8e7de6, 0xa87b0a1c):
        reader.read_int64()
        reader.read_int64()
    elif peer_constructor == 0x35a95cb9:
        reader.read_int64()

    vector_constructor = reader.read_uint32()
    count = reader.read_int32()
    msg_ids = [reader.read_int32() for _ in range(count)]

    conn = db.get_db()
    for mid in msg_ids:
        conn.execute("DELETE FROM scheduled_messages WHERE id = ? AND sender_id = ?", (mid, ctx.user_id))
    conn.commit()
    return R.build_updates_empty()


# ============================================================
# Forum Topic handlers
# ============================================================

def handle_channels_create_forum_topic(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()

    # inputChannel
    channel_constructor = reader.read_uint32()
    channel_id = reader.read_int64()
    access_hash = reader.read_int64()

    title = reader.read_string()

    icon_color = 0x6FB9F0
    if flags & 1:
        icon_color = reader.read_int32()

    icon_emoji_id = 0
    if flags & 8:
        icon_emoji_id = reader.read_int64()

    conn = db.get_db()
    conn.execute("""INSERT INTO forum_topics (channel_id, title, icon_color, icon_emoji_id, creator_id, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                 (channel_id, title, icon_color, icon_emoji_id, ctx.user_id, int(time.time())))
    topic_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit()

    return R.build_updates_empty()


def handle_channels_edit_forum_topic(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()

    channel_constructor = reader.read_uint32()
    channel_id = reader.read_int64()
    access_hash = reader.read_int64()

    topic_id = reader.read_int32()

    conn = db.get_db()
    if flags & 1:
        title = reader.read_string()
        conn.execute("UPDATE forum_topics SET title = ? WHERE id = ? AND channel_id = ?",
                     (title, topic_id, channel_id))
    if flags & 4:
        is_closed = reader.read_bool()
        conn.execute("UPDATE forum_topics SET is_closed = ? WHERE id = ? AND channel_id = ?",
                     (1 if is_closed else 0, topic_id, channel_id))
    conn.commit()
    return R.build_updates_empty()


def handle_channels_get_forum_topics(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()

    channel_constructor = reader.read_uint32()
    channel_id = reader.read_int64()
    access_hash = reader.read_int64()

    conn = db.get_db()
    topics = conn.execute("SELECT * FROM forum_topics WHERE channel_id = ? ORDER BY created_at DESC LIMIT 100",
                          (channel_id,)).fetchall()
    return R.build_forum_topics(topics)


def handle_channels_get_forum_topic(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_forum_topics([])


def handle_channels_update_pinned_forum_topic(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_channels_reorder_pinned_forum_topics(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


# ============================================================
# Group Call handlers
# ============================================================

def handle_phone_create_group_call(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()
    # inputPeer
    peer_constructor = reader.read_uint32()
    peer_id = 0
    if peer_constructor in (0x7b8e7de6, 0xa87b0a1c):
        peer_id = reader.read_int64()
        reader.read_int64()
    elif peer_constructor == 0x35a95cb9:
        peer_id = reader.read_int64()
    random_id = reader.read_int32()

    conn = db.get_db()
    call_access_hash = random.randint(1, 2**62)
    title = None
    if flags & 2:
        title = reader.read_string()

    conn.execute("""INSERT INTO group_calls (access_hash, chat_id, title, creator_id, participant_count, created_at)
                    VALUES (?, ?, ?, ?, 1, ?)""",
                 (call_access_hash, peer_id, title, ctx.user_id, int(time.time())))
    call_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO group_call_participants (call_id, user_id, joined_at) VALUES (?, ?, ?)",
                 (call_id, ctx.user_id, int(time.time())))
    conn.commit()

    call = conn.execute("SELECT * FROM group_calls WHERE id = ?", (call_id,)).fetchone()
    return R.build_updates_empty()


def handle_phone_join_group_call(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()
    # inputGroupCall
    call_id = reader.read_int64()
    access_hash = reader.read_int64()

    conn = db.get_db()
    conn.execute("INSERT OR IGNORE INTO group_call_participants (call_id, user_id, joined_at) VALUES (?, ?, ?)",
                 (call_id, ctx.user_id, int(time.time())))
    conn.execute("UPDATE group_calls SET participant_count = participant_count + 1 WHERE id = ?", (call_id,))
    conn.commit()
    return R.build_updates_empty()


def handle_phone_leave_group_call(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    call_id = reader.read_int64()
    access_hash = reader.read_int64()
    source = reader.read_int32()

    conn = db.get_db()
    conn.execute("DELETE FROM group_call_participants WHERE call_id = ? AND user_id = ?", (call_id, ctx.user_id))
    conn.execute("UPDATE group_calls SET participant_count = MAX(0, participant_count - 1) WHERE id = ?", (call_id,))
    conn.commit()
    return R.build_updates_empty()


def handle_phone_discard_group_call(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    call_id = reader.read_int64()
    access_hash = reader.read_int64()

    conn = db.get_db()
    conn.execute("UPDATE group_calls SET is_active = 0 WHERE id = ?", (call_id,))
    conn.execute("DELETE FROM group_call_participants WHERE call_id = ?", (call_id,))
    conn.commit()
    return R.build_updates_empty()


def handle_phone_get_group_call(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    call_id = reader.read_int64()
    access_hash = reader.read_int64()

    conn = db.get_db()
    call = conn.execute("SELECT * FROM group_calls WHERE id = ?", (call_id,)).fetchone()
    if not call:
        return R.build_group_call_empty()
    return R.build_group_call(call)


def handle_phone_toggle_group_call_settings(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_phone_edit_group_call_participant(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()


def handle_phone_get_group_participants(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    call_id = reader.read_int64()
    access_hash = reader.read_int64()

    conn = db.get_db()
    participants = conn.execute("SELECT * FROM group_call_participants WHERE call_id = ?", (call_id,)).fetchall()
    users = []
    for p in participants:
        u = conn.execute("SELECT * FROM users WHERE id = ?", (p['user_id'],)).fetchone()
        if u:
            users.append(u)
    return R.build_group_participants(participants, users)


# ============================================================
# Geolocation handlers
# ============================================================

def handle_messages_get_recent_locations(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_messages_messages([], [], [])


# ============================================================
# Import handlers
# ============================================================

def handle_messages_check_history_import_peer(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_checked_history_import_peer()


def handle_messages_check_history_import(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_checked_history_import_peer()


def handle_messages_init_history_import(data: bytes, ctx: RPCContext) -> bytes:
    import_id = random.randint(1, 2**62)
    return R.build_history_import_init(import_id)


def handle_messages_start_history_import(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)


# ============================================================
# Account TTL handlers
# ============================================================

def handle_account_set_account_ttl(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    # accountDaysTTL
    ttl_constructor = reader.read_uint32()
    days = reader.read_int32()

    conn = db.get_db()
    conn.execute("INSERT OR REPLACE INTO account_settings (user_id, account_ttl_days) VALUES (?, ?)",
                 (ctx.user_id, days))
    conn.commit()
    return R.build_bool(True)


def handle_account_get_account_ttl(data: bytes, ctx: RPCContext) -> bytes:
    conn = db.get_db()
    row = conn.execute("SELECT account_ttl_days FROM account_settings WHERE user_id = ?",
                       (ctx.user_id,)).fetchone()
    days = row['account_ttl_days'] if row else 365
    return R.build_account_days_ttl(days)


def handle_account_set_global_privacy_settings(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_global_privacy_settings()


def handle_account_get_global_privacy_settings(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_global_privacy_settings()


# ============================================================
# Additional stub handlers
# ============================================================

def handle_account_get_notify_settings(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xdbbaedcb)  # peerNotifySettings
    s.write_int32(0)  # flags — no overrides
    return s.get_bytes()

def handle_account_update_notify_settings(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)

def handle_account_get_notify_exceptions(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()

def handle_account_get_contact_sign_up_notification(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(False)

def handle_account_set_contact_sign_up_notification(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)

def handle_account_get_default_emoji_statuses(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xd08ce645)  # account.emojiStatusesNotModified
    return s.get_bytes()

def handle_account_get_themes(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xf41eb622)  # account.themesNotModified
    return s.get_bytes()

def handle_account_get_content_settings(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x57e28221)  # account.contentSettings
    s.write_int32(0)  # flags
    return s.get_bytes()

def handle_account_confirm_phone(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)

def handle_account_reset_authorization(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)

def handle_account_get_saved_ringtones(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xfbf6e4b1)  # account.savedRingtonesNotModified
    return s.get_bytes()

def handle_account_get_channel_default_emoji_statuses(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xd08ce645)  # account.emojiStatusesNotModified
    return s.get_bytes()

def handle_account_get_recent_emoji_statuses(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xd08ce645)  # account.emojiStatusesNotModified
    return s.get_bytes()

# --- Messages additional stubs ---

def handle_messages_get_peer_settings(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x6880b94d)  # messages.peerSettings
    s.write_uint32(0xa518110d)  # peerSettings
    s.write_int32(0)  # flags
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # chats
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # users
    return s.get_bytes()

def handle_messages_get_chats(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_messages_chats([])

def handle_messages_get_common_chats(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_messages_chats([])

def handle_messages_get_web_page(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xeb1477e8)  # webPageNotModified
    s.write_int32(0)  # flags
    return s.get_bytes()

def handle_messages_get_web_page_preview(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xeb1477e8)  # webPageNotModified
    s.write_int32(0)
    return s.get_bytes()

def handle_messages_get_message_edit_data(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x26b5dde6)  # messages.messageEditData
    s.write_int32(0)  # flags
    return s.get_bytes()

def handle_messages_get_messages_views(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xb6c4f543)  # messages.messageViews
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # views
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # chats
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # users
    return s.get_bytes()

def handle_messages_get_attached_stickers(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # vector<StickerSetCovered>
    return s.get_bytes()

def handle_messages_get_saved_gifs(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xe8025ca2)  # messages.savedGifsNotModified
    return s.get_bytes()

def handle_messages_get_featured_stickers(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xc6dc0c66)  # messages.featuredStickersNotModified
    s.write_int32(0)  # count
    return s.get_bytes()

def handle_messages_get_mask_stickers(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xf1749a22)  # messages.allStickersNotModified
    return s.get_bytes()

def handle_messages_get_all_chats(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_messages_chats([])

def handle_messages_get_onlines(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xf49d7eb6)  # chatOnlines
    s.write_int32(0)  # onlines count
    return s.get_bytes()

def handle_messages_get_available_reactions(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x9f071957)  # messages.availableReactionsNotModified
    return s.get_bytes()

def handle_messages_get_unread_mentions(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_messages_messages([], [], [])

def handle_messages_read_mentions(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_affected_history(0, 0)

def handle_messages_get_search_counters(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # vector<messages.SearchCounter>
    return s.get_bytes()

def handle_messages_get_extended_media(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()

def handle_messages_get_emoji_groups(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x6fb4ad87)  # messages.emojiGroupsNotModified
    return s.get_bytes()

def handle_messages_get_emoji_sticker_groups(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x6fb4ad87)  # messages.emojiGroupsNotModified
    return s.get_bytes()

def handle_messages_get_available_effects(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xd1ed9a5b)  # messages.availableEffectsNotModified
    return s.get_bytes()

def handle_messages_toggle_peer_translations(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)

def handle_messages_get_pinned_dialogs(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xd63a1b4b)  # messages.peerDialogs
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # dialogs
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # messages
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # chats
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # users
    # state
    s.write_uint32(0xa56c2a3e)  # updates.state
    s.write_int32(0); s.write_int32(0); s.write_int32(int(time.time()))
    s.write_int32(0); s.write_int32(0)
    return s.get_bytes()

def handle_messages_toggle_dialog_pin(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)

def handle_messages_reorder_pinned_dialogs(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)

def handle_messages_read_featured_stickers(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)

def handle_messages_get_archived_stickers(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x4fcba9c8)  # messages.archivedStickers
    s.write_int32(0)  # count
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # sets
    return s.get_bytes()

def handle_messages_set_game_score(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()

def handle_messages_get_game_high_scores(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x9a3bfd99)  # messages.highScores
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # scores
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # users
    return s.get_bytes()

def handle_messages_get_unread_reactions(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_messages_messages([], [], [])

def handle_messages_read_reactions(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_affected_history(0, 0)

def handle_messages_report_spam(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)

def handle_messages_report(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)

def handle_messages_get_default_history_ttl(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x43b46b20)  # defaultHistoryTTL
    s.write_int32(0)  # period (0 = disabled)
    return s.get_bytes()

def handle_messages_set_default_history_ttl(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)

def handle_messages_send_bot_requested_peer(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()

def handle_messages_hide_all_chat_join_requests(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()

# --- Contacts additional stubs ---

def handle_contacts_get_top_peers(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xb52c939d)  # contacts.topPeersDisabled
    return s.get_bytes()

def handle_contacts_reset_top_peer_rating(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)

def handle_contacts_get_located(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()

def handle_contacts_get_saved(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # empty vector
    return s.get_bytes()

def handle_contacts_toggle_top_peers(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)

# --- Channels additional stubs ---

def handle_channels_get_admin_log(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xed8af74d)  # channels.adminLogResults
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # events
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # chats
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # users
    return s.get_bytes()

def handle_channels_read_history(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)

def handle_channels_delete_messages(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_affected_messages(0, 0)

def handle_channels_read_message_contents(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)

def handle_channels_toggle_signatures(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()

def handle_channels_toggle_slow_mode(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()

def handle_channels_get_send_as(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xf496b0c6)  # channels.sendAsPeers
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # peers
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # chats
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # users
    return s.get_bytes()

def handle_channels_get_inactive_channels(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xa68b0b97)  # messages.inactiveChats
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # dates
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # chats
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # users
    return s.get_bytes()

def handle_channels_toggle_join_to_send(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()

def handle_channels_toggle_join_request(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_updates_empty()

# --- Help additional stubs ---

def handle_help_get_premium_promo(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x8a4f3c29)  # help.premiumPromo
    s.write_string("")  # status_text
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # status_entities
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # video_sections
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # videos
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # period_options
    s.write_uint32(0x1cb5c415); s.write_int32(0)  # users
    return s.get_bytes()

def handle_help_dismiss_suggestion(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)

def handle_help_get_support(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x17c6b5f6)  # help.support
    s.write_string("Custom Server Support")
    # user (minimal)
    s.write_uint32(0x215c4438)  # user
    s.write_int32(0)  # flags
    s.write_int64(777000)  # id
    s.write_int64(0)  # access_hash
    s.write_string("Support")
    s.write_string("")
    s.write_string("support")
    s.write_string("")  # phone
    return s.get_bytes()

def handle_help_get_invite_text(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x18cb9f78)  # help.inviteText
    s.write_string("Join our messenger!")
    return s.get_bytes()

def handle_help_save_app_log(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)

def handle_help_get_passport_config(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xbfb9f457)  # help.passportConfigNotModified
    return s.get_bytes()

def handle_help_get_deep_link_info(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x66afa166)  # help.deepLinkInfoEmpty
    return s.get_bytes()

def handle_help_get_support_name(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x8c05f1c9)  # help.supportName
    s.write_string("Custom Server")
    return s.get_bytes()

def handle_help_get_promo_data(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x98f6ac75)  # help.promoDataEmpty
    s.write_int32(int(time.time()) + 86400)  # expires
    return s.get_bytes()

def handle_help_hide_promo_data(data: bytes, ctx: RPCContext) -> bytes:
    return R.build_bool(True)

def handle_help_get_peer_colors(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x2ba1f5ce)  # help.peerColorsNotModified
    return s.get_bytes()

def handle_help_get_peer_profile_colors(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x2ba1f5ce)  # help.peerColorsNotModified
    return s.get_bytes()

def handle_help_get_timezones_list(data: bytes, ctx: RPCContext) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x970708cc)  # help.timezonesListNotModified
    return s.get_bytes()


# ============================================================
# HANDLERS map
# ============================================================

HANDLERS = {
    # Auth
    C.AUTH_SEND_CODE: handle_auth_send_code,
    C.AUTH_RESEND_CODE: handle_auth_resend_code,
    C.AUTH_SIGN_IN: handle_auth_sign_in,
    C.AUTH_SIGN_UP: handle_auth_sign_up,
    C.AUTH_LOG_OUT: handle_auth_log_out,
    C.AUTH_CHECK_PASSWORD: handle_auth_check_password,
    C.AUTH_EXPORT_AUTHORIZATION: handle_auth_export_authorization,
    C.AUTH_IMPORT_AUTHORIZATION: handle_auth_import_authorization,
    C.AUTH_BIND_TEMP_AUTH_KEY: handle_auth_bind_temp,

    # Users
    C.USERS_GET_USERS: handle_users_get_users,
    C.USERS_GET_FULL_USER: handle_users_get_full_user,

    # Account
    C.ACCOUNT_UPDATE_PROFILE: handle_account_update_profile,
    C.ACCOUNT_UPDATE_STATUS: handle_account_update_status,
    C.ACCOUNT_UPDATE_USERNAME: handle_account_update_username,
    C.ACCOUNT_GET_PASSWORD: handle_account_get_password,
    C.ACCOUNT_REGISTER_DEVICE: handle_account_register_device,
    C.ACCOUNT_UNREGISTER_DEVICE: handle_account_unregister_device,
    C.ACCOUNT_GET_AUTHORIZATIONS: handle_account_get_authorizations,
    C.ACCOUNT_GET_PRIVACY: handle_account_get_privacy,
    C.ACCOUNT_SET_PRIVACY: handle_account_set_privacy,
    C.ACCOUNT_GET_WALL_PAPERS: handle_account_get_wall_papers,

    # Contacts
    C.CONTACTS_GET_CONTACTS: handle_contacts_get_contacts,
    C.CONTACTS_IMPORT_CONTACTS: handle_contacts_import_contacts,
    C.CONTACTS_DELETE_CONTACTS: handle_contacts_delete_contacts,
    C.CONTACTS_GET_BLOCKED: handle_contacts_get_blocked,
    C.CONTACTS_BLOCK: handle_contacts_block,
    C.CONTACTS_UNBLOCK: handle_contacts_unblock,
    C.CONTACTS_SEARCH: handle_contacts_search,
    C.CONTACTS_RESOLVE_USERNAME: handle_contacts_resolve_username,

    # Messages
    C.MESSAGES_GET_MESSAGES: handle_messages_get_messages,
    C.MESSAGES_GET_DIALOGS: handle_messages_get_dialogs,
    C.MESSAGES_GET_HISTORY: handle_messages_get_history,
    C.MESSAGES_SEND_MESSAGE: handle_messages_send_message,
    C.MESSAGES_SEND_MEDIA: handle_messages_send_media,
    C.MESSAGES_FORWARD_MESSAGES: handle_messages_forward_messages,
    C.MESSAGES_EDIT_MESSAGE: handle_messages_edit_message,
    C.MESSAGES_DELETE_MESSAGES: handle_messages_delete_messages,
    C.MESSAGES_READ_HISTORY: handle_messages_read_history,
    C.MESSAGES_RECEIVED_MESSAGES: handle_messages_received_messages,
    C.MESSAGES_SET_TYPING: handle_messages_set_typing,
    C.MESSAGES_SEARCH: handle_messages_search,
    C.MESSAGES_GET_PEER_DIALOGS: handle_messages_get_peer_dialogs,
    C.MESSAGES_SEND_REACTION: handle_messages_send_reaction,
    C.MESSAGES_GET_MESSAGES_REACTIONS: handle_messages_get_messages_reactions,
    C.MESSAGES_UPDATE_PINNED_MESSAGE: handle_messages_update_pinned_message,
    C.MESSAGES_GET_PINNED_MESSAGES: handle_messages_get_pinned_messages,
    C.MESSAGES_SET_CHAT_WALL_PAPER: handle_messages_set_chat_wall_paper,

    # Chat management
    C.MESSAGES_CREATE_CHAT: handle_messages_create_chat,
    C.MESSAGES_EDIT_CHAT_TITLE: handle_messages_edit_chat_title,
    C.MESSAGES_EDIT_CHAT_PHOTO: handle_messages_edit_chat_photo,
    C.MESSAGES_ADD_CHAT_USER: handle_messages_add_chat_user,
    C.MESSAGES_DELETE_CHAT_USER: handle_messages_delete_chat_user,
    C.MESSAGES_GET_FULL_CHAT: handle_messages_get_full_chat,

    # Channels
    C.CHANNELS_CREATE_CHANNEL: handle_channels_create,
    C.CHANNELS_EDIT_TITLE: handle_channels_edit_title,
    C.CHANNELS_EDIT_ABOUT: handle_channels_edit_about,
    C.CHANNELS_EDIT_PHOTO: handle_channels_edit_photo,
    C.CHANNELS_JOIN_CHANNEL: handle_channels_join,
    C.CHANNELS_LEAVE_CHANNEL: handle_channels_leave,
    C.CHANNELS_INVITE_TO_CHANNEL: handle_channels_invite,
    C.CHANNELS_DELETE_CHANNEL: handle_channels_delete,
    C.CHANNELS_GET_CHANNELS: handle_channels_get_channels,
    C.CHANNELS_GET_FULL_CHANNEL: handle_channels_get_full_channel,
    C.CHANNELS_EDIT_ADMIN: handle_channels_edit_admin,
    C.CHANNELS_EDIT_BANNED: handle_channels_edit_banned,
    C.CHANNELS_GET_PARTICIPANTS: handle_channels_get_participants,

    # Upload
    C.UPLOAD_SAVE_FILE_PART: handle_upload_save_file_part,
    C.UPLOAD_GET_FILE: handle_upload_get_file,
    C.UPLOAD_SAVE_BIG_FILE_PART: handle_upload_save_big_file_part,

    # Updates
    C.UPDATES_GET_STATE: handle_updates_get_state,
    C.UPDATES_GET_DIFFERENCE: handle_updates_get_difference,
    C.UPDATES_GET_CHANNEL_DIFFERENCE: handle_updates_get_channel_difference,

    # Help
    C.HELP_GET_CONFIG: handle_help_get_config,
    C.HELP_GET_NEAREST_DC: handle_help_get_nearest_dc,
    C.HELP_GET_APP_UPDATE: handle_help_get_app_update,
    C.HELP_GET_CDN_CONFIG: handle_help_get_cdn_config,
    C.HELP_GET_APP_CONFIG: handle_help_get_app_config,
    C.HELP_GET_TERMS_OF_SERVICE_UPDATE: handle_help_get_terms_of_service,
    C.HELP_GET_COUNTRIES_LIST: handle_help_get_countries_list,

    # Stickers
    C.MESSAGES_GET_ALL_STICKERS: handle_get_all_stickers,
    C.MESSAGES_GET_STICKER_SET: handle_get_sticker_set,
    C.MESSAGES_INSTALL_STICKER_SET: handle_install_sticker_set,
    C.MESSAGES_GET_RECENT_STICKERS: handle_get_recent_stickers,
    C.MESSAGES_SAVE_RECENT_STICKER: handle_save_recent_sticker,
    C.MESSAGES_GET_FAVED_STICKERS: handle_get_faved_stickers,
    C.MESSAGES_FAVE_STICKER: handle_fave_sticker,

    # Polls
    C.MESSAGES_SEND_VOTE: handle_send_vote,
    C.MESSAGES_GET_POLL_RESULTS: handle_get_poll_results,
    C.MESSAGES_GET_POLL_VOTES: handle_get_poll_votes,

    # Photos
    C.PHOTOS_UPDATE_PROFILE_PHOTO: handle_photos_update_profile_photo,
    C.PHOTOS_UPLOAD_PROFILE_PHOTO: handle_photos_upload_profile_photo,

    # Stories
    C.STORIES_GET_ALL_STORIES: handle_stories_get_all,
    C.STORIES_GET_PEER_STORIES: handle_stories_get_peer,
    C.STORIES_SEND_STORY: handle_stories_send,
    C.STORIES_DELETE_STORIES: handle_stories_delete,
    C.STORIES_GET_STORIES_VIEWS: handle_stories_get_views,
    C.STORIES_READ_STORIES: handle_stories_read,

    # Langpack
    C.LANGPACK_GET_LANGUAGES: handle_langpack_get_languages,
    C.LANGPACK_GET_LANG_PACK: handle_langpack_get_lang_pack,
    C.LANGPACK_GET_STRINGS: handle_langpack_get_strings,
    C.LANGPACK_GET_DIFFERENCE_2: handle_langpack_get_difference,

    # Service/MTProto
    C.PING: handle_ping,
    C.PING_DELAY_DISCONNECT: handle_ping_delay_disconnect,
    C.MSGS_ACK: handle_msgs_ack,
    C.DESTROY_SESSION: handle_destroy_session,
    C.GET_FUTURE_SALTS: handle_get_future_salts,
    C.RPC_DROP_ANSWER: handle_rpc_drop_answer,

    # Phone Calls (VoIP)
    C.PHONE_REQUEST_CALL: handle_phone_request_call,
    C.PHONE_ACCEPT_CALL: handle_phone_accept_call,
    C.PHONE_CONFIRM_CALL: handle_phone_confirm_call,
    C.PHONE_DISCARD_CALL: handle_phone_discard_call,
    C.PHONE_RECEIVED_CALL: handle_phone_received_call,
    C.PHONE_SET_CALL_RATING: handle_phone_set_call_rating,
    C.PHONE_SAVE_CALL_DEBUG: handle_phone_save_call_debug,

    # Group Calls
    C.PHONE_CREATE_GROUP_CALL: handle_phone_create_group_call,
    C.PHONE_JOIN_GROUP_CALL: handle_phone_join_group_call,
    C.PHONE_LEAVE_GROUP_CALL: handle_phone_leave_group_call,
    C.PHONE_DISCARD_GROUP_CALL: handle_phone_discard_group_call,
    C.PHONE_GET_GROUP_CALL: handle_phone_get_group_call,
    C.PHONE_TOGGLE_GROUP_CALL_SETTINGS: handle_phone_toggle_group_call_settings,
    C.PHONE_EDIT_GROUP_CALL_PARTICIPANT: handle_phone_edit_group_call_participant,
    C.PHONE_GET_GROUP_PARTICIPANTS: handle_phone_get_group_participants,

    # Secret Chats
    C.MESSAGES_GET_DH_CONFIG: handle_messages_get_dh_config,
    C.MESSAGES_REQUEST_ENCRYPTION: handle_messages_request_encryption,
    C.MESSAGES_ACCEPT_ENCRYPTION: handle_messages_accept_encryption,
    C.MESSAGES_DISCARD_ENCRYPTION: handle_messages_discard_encryption,
    C.MESSAGES_SEND_ENCRYPTED: handle_messages_send_encrypted,
    C.MESSAGES_SEND_ENCRYPTED_FILE: handle_messages_send_encrypted_file,
    C.MESSAGES_SEND_ENCRYPTED_SERVICE: handle_messages_send_encrypted_service,
    C.MESSAGES_READ_ENCRYPTED_HISTORY: handle_messages_read_encrypted_history,

    # Bots
    C.MESSAGES_GET_BOT_CALLBACK_ANSWER: handle_messages_get_bot_callback_answer,
    C.MESSAGES_SET_BOT_CALLBACK_ANSWER: handle_messages_set_bot_callback_answer,
    C.MESSAGES_GET_INLINE_BOT_RESULTS: handle_messages_get_inline_bot_results,
    C.MESSAGES_SEND_INLINE_BOT_RESULT: handle_messages_send_inline_bot_result,
    C.MESSAGES_SET_BOT_COMMANDS: handle_messages_set_bot_commands,
    C.MESSAGES_GET_BOT_COMMANDS: handle_messages_get_bot_commands,

    # Drafts
    C.MESSAGES_SAVE_DRAFT: handle_messages_save_draft,
    C.MESSAGES_GET_ALL_DRAFTS: handle_messages_get_all_drafts,
    C.MESSAGES_CLEAR_ALL_DRAFTS: handle_messages_clear_all_drafts,

    # Dialog Filters / Folders
    C.MESSAGES_GET_DIALOG_FILTERS: handle_messages_get_dialog_filters,
    C.MESSAGES_UPDATE_DIALOG_FILTER: handle_messages_update_dialog_filter,
    C.MESSAGES_UPDATE_DIALOG_FILTERS_ORDER: handle_messages_update_dialog_filters_order,
    C.MESSAGES_GET_DIALOG_UNREAD_MARKS: handle_messages_get_dialog_unread_marks,
    C.MESSAGES_MARK_DIALOG_UNREAD: handle_messages_mark_dialog_unread,

    # Scheduled Messages
    C.MESSAGES_GET_SCHEDULED_HISTORY: handle_messages_get_scheduled_history,
    C.MESSAGES_GET_SCHEDULED_MESSAGES: handle_messages_get_scheduled_messages,
    C.MESSAGES_SEND_SCHEDULED_MESSAGES: handle_messages_send_scheduled_messages,
    C.MESSAGES_DELETE_SCHEDULED_MESSAGES: handle_messages_delete_scheduled_messages,

    # Forum Topics
    C.CHANNELS_CREATE_FORUM_TOPIC: handle_channels_create_forum_topic,
    C.CHANNELS_EDIT_FORUM_TOPIC: handle_channels_edit_forum_topic,
    C.CHANNELS_GET_FORUM_TOPICS: handle_channels_get_forum_topics,
    C.CHANNELS_GET_FORUM_TOPIC: handle_channels_get_forum_topic,
    C.CHANNELS_UPDATE_PINNED_FORUM_TOPIC: handle_channels_update_pinned_forum_topic,
    C.CHANNELS_REORDER_PINNED_FORUM_TOPICS: handle_channels_reorder_pinned_forum_topics,

    # Geolocation
    C.MESSAGES_GET_RECENT_LOCATIONS: handle_messages_get_recent_locations,

    # Import
    C.MESSAGES_CHECK_HISTORY_IMPORT_PEER: handle_messages_check_history_import_peer,
    C.MESSAGES_CHECK_HISTORY_IMPORT: handle_messages_check_history_import,
    C.MESSAGES_INIT_HISTORY_IMPORT: handle_messages_init_history_import,
    C.MESSAGES_START_HISTORY_IMPORT: handle_messages_start_history_import,

    # Account TTL
    C.ACCOUNT_SET_ACCOUNT_TTL: handle_account_set_account_ttl,
    C.ACCOUNT_GET_ACCOUNT_TTL: handle_account_get_account_ttl,
    C.ACCOUNT_SET_GLOBAL_PRIVACY_SETTINGS: handle_account_set_global_privacy_settings,
    C.ACCOUNT_GET_GLOBAL_PRIVACY_SETTINGS: handle_account_get_global_privacy_settings,

    # Account (additional)
    C.ACCOUNT_GET_NOTIFY_SETTINGS: handle_account_get_notify_settings,
    C.ACCOUNT_UPDATE_NOTIFY_SETTINGS: handle_account_update_notify_settings,
    C.ACCOUNT_GET_NOTIFY_EXCEPTIONS: handle_account_get_notify_exceptions,
    C.ACCOUNT_GET_CONTACT_SIGN_UP_NOTIFICATION: handle_account_get_contact_sign_up_notification,
    C.ACCOUNT_SET_CONTACT_SIGN_UP_NOTIFICATION: handle_account_set_contact_sign_up_notification,
    C.ACCOUNT_GET_DEFAULT_EMOJI_STATUSES: handle_account_get_default_emoji_statuses,
    C.ACCOUNT_GET_THEMES: handle_account_get_themes,
    C.ACCOUNT_GET_CONTENT_SETTINGS: handle_account_get_content_settings,
    C.ACCOUNT_CONFIRM_PHONE: handle_account_confirm_phone,
    C.ACCOUNT_RESET_AUTHORIZATION: handle_account_reset_authorization,
    C.ACCOUNT_GET_SAVED_RINGTONES: handle_account_get_saved_ringtones,
    C.ACCOUNT_GET_CHANNEL_DEFAULT_EMOJI_STATUSES: handle_account_get_channel_default_emoji_statuses,
    C.ACCOUNT_GET_RECENT_EMOJI_STATUSES: handle_account_get_recent_emoji_statuses,

    # Messages (additional)
    C.MESSAGES_GET_PEER_SETTINGS: handle_messages_get_peer_settings,
    C.MESSAGES_GET_CHATS: handle_messages_get_chats,
    C.MESSAGES_GET_COMMON_CHATS: handle_messages_get_common_chats,
    C.MESSAGES_GET_WEB_PAGE: handle_messages_get_web_page,
    C.MESSAGES_GET_WEB_PAGE_PREVIEW: handle_messages_get_web_page_preview,
    C.MESSAGES_GET_MESSAGE_EDIT_DATA: handle_messages_get_message_edit_data,
    C.MESSAGES_GET_MESSAGES_VIEWS: handle_messages_get_messages_views,
    C.MESSAGES_GET_ATTACHED_STICKERS: handle_messages_get_attached_stickers,
    C.MESSAGES_GET_SAVED_GIFS: handle_messages_get_saved_gifs,
    C.MESSAGES_GET_FEATURED_STICKERS: handle_messages_get_featured_stickers,
    C.MESSAGES_GET_MASK_STICKERS: handle_messages_get_mask_stickers,
    C.MESSAGES_GET_ALL_CHATS: handle_messages_get_all_chats,
    C.MESSAGES_GET_ONLINES: handle_messages_get_onlines,
    C.MESSAGES_GET_AVAILABLE_REACTIONS: handle_messages_get_available_reactions,
    C.MESSAGES_GET_UNREAD_MENTIONS: handle_messages_get_unread_mentions,
    C.MESSAGES_READ_MENTIONS: handle_messages_read_mentions,
    C.MESSAGES_GET_SEARCH_COUNTERS: handle_messages_get_search_counters,
    C.MESSAGES_GET_EXTENDED_MEDIA: handle_messages_get_extended_media,
    C.MESSAGES_GET_EMOJI_GROUPS: handle_messages_get_emoji_groups,
    C.MESSAGES_GET_EMOJI_STICKER_GROUPS: handle_messages_get_emoji_sticker_groups,
    C.MESSAGES_GET_AVAILABLE_EFFECTS: handle_messages_get_available_effects,
    C.MESSAGES_TOGGLE_PEER_TRANSLATIONS: handle_messages_toggle_peer_translations,
    C.MESSAGES_GET_PINNED_DIALOGS: handle_messages_get_pinned_dialogs,
    C.MESSAGES_TOGGLE_DIALOG_PIN: handle_messages_toggle_dialog_pin,
    C.MESSAGES_REORDER_PINNED_DIALOGS: handle_messages_reorder_pinned_dialogs,
    C.MESSAGES_READ_FEATURED_STICKERS: handle_messages_read_featured_stickers,
    C.MESSAGES_GET_ARCHIVED_STICKERS: handle_messages_get_archived_stickers,
    C.MESSAGES_SET_GAME_SCORE: handle_messages_set_game_score,
    C.MESSAGES_GET_GAME_HIGH_SCORES: handle_messages_get_game_high_scores,
    C.MESSAGES_GET_UNREAD_REACTIONS: handle_messages_get_unread_reactions,
    C.MESSAGES_READ_REACTIONS: handle_messages_read_reactions,
    C.MESSAGES_REPORT_SPAM: handle_messages_report_spam,
    C.MESSAGES_REPORT: handle_messages_report,
    C.MESSAGES_GET_DEFAULT_HISTORY_TTL: handle_messages_get_default_history_ttl,
    C.MESSAGES_SET_DEFAULT_HISTORY_TTL: handle_messages_set_default_history_ttl,
    C.MESSAGES_SEND_BOT_REQUESTED_PEER: handle_messages_send_bot_requested_peer,
    C.MESSAGES_HIDE_ALL_CHAT_JOIN_REQUESTS: handle_messages_hide_all_chat_join_requests,

    # Contacts (additional)
    C.CONTACTS_GET_TOP_PEERS: handle_contacts_get_top_peers,
    C.CONTACTS_RESET_TOP_PEER_RATING: handle_contacts_reset_top_peer_rating,
    C.CONTACTS_GET_LOCATED: handle_contacts_get_located,
    C.CONTACTS_GET_SAVED: handle_contacts_get_saved,
    C.CONTACTS_TOGGLE_TOP_PEERS: handle_contacts_toggle_top_peers,

    # Channels (additional)
    C.CHANNELS_GET_ADMIN_LOG: handle_channels_get_admin_log,
    C.CHANNELS_READ_HISTORY: handle_channels_read_history,
    C.CHANNELS_DELETE_MESSAGES: handle_channels_delete_messages,
    C.CHANNELS_READ_MESSAGE_CONTENTS: handle_channels_read_message_contents,
    C.CHANNELS_TOGGLE_SIGNATURES: handle_channels_toggle_signatures,
    C.CHANNELS_TOGGLE_SLOW_MODE: handle_channels_toggle_slow_mode,
    C.CHANNELS_GET_SEND_AS: handle_channels_get_send_as,
    C.CHANNELS_GET_INACTIVE_CHANNELS: handle_channels_get_inactive_channels,
    C.CHANNELS_TOGGLE_JOIN_TO_SEND: handle_channels_toggle_join_to_send,
    C.CHANNELS_TOGGLE_JOIN_REQUEST: handle_channels_toggle_join_request,

    # Help (additional)
    C.HELP_GET_PREMIUM_PROMO: handle_help_get_premium_promo,
    C.HELP_DISMISS_SUGGESTION: handle_help_dismiss_suggestion,
    C.HELP_GET_SUPPORT: handle_help_get_support,
    C.HELP_GET_INVITE_TEXT: handle_help_get_invite_text,
    C.HELP_SAVE_APP_LOG: handle_help_save_app_log,
    C.HELP_GET_PASSPORT_CONFIG: handle_help_get_passport_config,
    C.HELP_GET_DEEP_LINK_INFO: handle_help_get_deep_link_info,
    C.HELP_GET_SUPPORT_NAME: handle_help_get_support_name,
    C.HELP_GET_PROMO_DATA: handle_help_get_promo_data,
    C.HELP_HIDE_PROMO_DATA: handle_help_hide_promo_data,
    C.HELP_GET_PEER_COLORS: handle_help_get_peer_colors,
    C.HELP_GET_PEER_PROFILE_COLORS: handle_help_get_peer_profile_colors,
    C.HELP_GET_TIMEZONES_LIST: handle_help_get_timezones_list,
}
