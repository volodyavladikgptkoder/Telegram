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

    if phone_code and user['phone_code'] != phone_code:
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

def handle_upload_save_file_part(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    file_id = reader.read_int64()
    file_part = reader.read_int32()
    file_bytes = reader.read_bytes()

    conn = db.get_db()
    conn.execute("INSERT OR REPLACE INTO file_parts (file_id, part_num, data) VALUES (?, ?, ?)",
                 (file_id, file_part, file_bytes))
    conn.commit()

    return R.build_bool(True)


def handle_upload_save_big_file_part(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    file_id = reader.read_int64()
    file_part = reader.read_int32()
    file_total_parts = reader.read_int32()
    file_bytes = reader.read_bytes()

    conn = db.get_db()
    conn.execute("INSERT OR REPLACE INTO file_parts (file_id, part_num, data) VALUES (?, ?, ?)",
                 (file_id, file_part, file_bytes))
    conn.commit()

    return R.build_bool(True)


def handle_upload_get_file(data: bytes, ctx: RPCContext) -> bytes:
    reader = TLDeserializer(data)
    reader.read_uint32()
    flags = reader.read_int32()

    location_constructor = reader.read_uint32()

    conn = db.get_db()
    # Return empty file for now
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
}
