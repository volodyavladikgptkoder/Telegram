"""
TL response builders — construct serialized TL objects for responses.
Each function returns bytes representing a serialized TL object.
"""

import time
import os
import random
import struct

from mtproto_server.tl_serialization import TLSerializer


# ============================================================
# Basic types
# ============================================================

def build_bool(value: bool) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x997275b5 if value else 0xbc799737)
    return s.get_bytes()


def build_rpc_error_raw(code: int, message: str) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x2144ca19)  # rpc_error
    s.write_int32(code)
    s.write_string(message)
    return s.get_bytes()


def build_pong(ping_id: int) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x347773c5)  # pong
    s.write_int64(0)  # msg_id (will be set by caller)
    s.write_int64(ping_id)
    return s.get_bytes()


def build_destroy_session_ok(session_id: int) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xe22045fc)  # destroy_session_ok
    s.write_int64(session_id)
    return s.get_bytes()


def build_future_salts(num: int) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xae500895)  # future_salts
    s.write_int64(0)  # req_msg_id
    s.write_int32(int(time.time()))  # now

    salts_count = min(num, 8)
    s.write_int32(salts_count)
    now = int(time.time())
    for i in range(salts_count):
        s.write_int32(now + i * 3600)  # valid_since
        s.write_int32(now + (i + 1) * 3600)  # valid_until
        s.write_int64(random.randint(1, 2**62))  # salt
    return s.get_bytes()


def build_rpc_answer_dropped() -> bytes:
    s = TLSerializer()
    s.write_uint32(0x5e2ad36e)  # rpc_answer_unknown
    return s.get_bytes()


# ============================================================
# AUTH responses
# ============================================================

def build_auth_sent_code(phone_code_hash: str, code_length: int) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x2390fe44)  # auth.sentCode
    s.write_int32(2)  # flags: has next_type

    # type: auth.sentCodeTypeApp
    s.write_uint32(0x3dbb5986)  # sentCodeTypeApp
    s.write_int32(code_length)

    s.write_string(phone_code_hash)

    # next_type: auth.codeTypeSms
    s.write_uint32(0x72a3158c)  # codeTypeSms

    s.write_int32(120)  # timeout
    return s.get_bytes()


def build_auth_authorization(user) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x2ea2c0d4)  # auth.authorization
    s.write_int32(0)  # flags
    _write_user(s, user)
    return s.get_bytes()


def build_auth_logged_out() -> bytes:
    s = TLSerializer()
    s.write_uint32(0xc3a2835f)  # auth.loggedOut
    s.write_int32(0)  # flags
    return s.get_bytes()


def build_auth_exported_authorization(user_id: int) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xb434e2b8)  # auth.exportedAuthorization
    s.write_int64(user_id)
    s.write_bytes(os.urandom(128))  # bytes
    return s.get_bytes()


# ============================================================
# USER type
# ============================================================

def _write_user(s: TLSerializer, user):
    if user is None:
        s.write_uint32(0xd3bc4b7a)  # userEmpty
        s.write_int64(0)
        return

    s.write_uint32(0x215c4438)  # user
    flags = 0
    flags |= (1 << 0) if user['access_hash'] else 0  # has access_hash
    flags |= (1 << 1) if user['first_name'] else 0   # has first_name
    flags |= (1 << 2) if user['last_name'] else 0    # has last_name
    flags |= (1 << 3) if user['username'] else 0     # has username
    flags |= (1 << 4) if user['phone'] else 0        # has phone
    flags |= (1 << 5)  # has photo (even if empty)
    flags |= (1 << 6)  # has status

    s.write_int32(flags)
    s.write_int32(0)  # flags2

    s.write_int64(user['id'])

    if flags & (1 << 0):
        s.write_int64(user['access_hash'] or 0)
    if flags & (1 << 1):
        s.write_string(user['first_name'] or '')
    if flags & (1 << 2):
        s.write_string(user['last_name'] or '')
    if flags & (1 << 3):
        s.write_string(user['username'] or '')
    if flags & (1 << 4):
        s.write_string(user['phone'] or '')
    if flags & (1 << 5):
        # userProfilePhotoEmpty
        s.write_uint32(0x4f11bae1)
    if flags & (1 << 6):
        if user['is_online']:
            s.write_uint32(0xedb93949)  # userStatusOnline
            s.write_int32(int(time.time()) + 300)
        else:
            s.write_uint32(0x8c703f)  # userStatusOffline (simplified)
            s.write_int32(user['last_seen'] or 0)


def build_user(user) -> bytes:
    s = TLSerializer()
    _write_user(s, user)
    return s.get_bytes()


def build_user_full(user) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xe22045fc)  # users.userFull
    s.write_int32(0)  # flags

    # fullUser
    s.write_uint32(0xcc997720)  # userFull
    s.write_int32(0)  # flags
    s.write_int64(user['id'])
    s.write_string(user['bio'] or '')

    # settings
    s.write_uint32(0xa1c69e91)  # peerSettings
    s.write_int32(0)  # flags

    # notifySettings
    s.write_uint32(0xaf509d20)  # peerNotifySettings
    s.write_int32(0)

    s.write_int32(0)  # common_chats_count

    # chats vector (empty)
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)

    # users vector
    s.write_uint32(0x1cb5c415)
    s.write_int32(1)
    _write_user(s, user)

    return s.get_bytes()


def build_vector_users(users) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x1cb5c415)  # vector
    s.write_int32(len(users))
    for user in users:
        _write_user(s, user)
    return s.get_bytes()


# ============================================================
# CONTACTS responses
# ============================================================

def build_contacts(contacts, user_id) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xeae87e42)  # contacts.contacts
    s.write_uint32(0x1cb5c415)  # vector (contacts)
    s.write_int32(len(contacts))
    for c in contacts:
        s.write_uint32(0x145ade0b)  # contact
        s.write_int64(c['id'])
        s.write_bool(False)  # mutual

    s.write_int32(0)  # savedCount

    # users vector
    s.write_uint32(0x1cb5c415)
    s.write_int32(len(contacts))
    for c in contacts:
        _write_user(s, c)

    return s.get_bytes()


def build_contacts_imported(imported_ids, users) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x77d01c3b)  # contacts.importedContacts

    # imported vector
    s.write_uint32(0x1cb5c415)
    s.write_int32(len(imported_ids))
    for uid in imported_ids:
        s.write_uint32(0xc13e3c50)  # importedContact
        s.write_int64(uid)
        s.write_int32(0)  # client_id

    # popular_invites (empty)
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)

    # retry_contacts (empty)
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)

    # users
    s.write_uint32(0x1cb5c415)
    s.write_int32(len(users))
    for u in users:
        _write_user(s, u)

    return s.get_bytes()


def build_contacts_blocked() -> bytes:
    s = TLSerializer()
    s.write_uint32(0xade1591)  # contacts.blocked
    # blocked (empty vector)
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    # chats (empty vector)
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    # users (empty vector)
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    return s.get_bytes()


def build_contacts_found(users) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xb3134d9d)  # contacts.found
    # my_results (empty)
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    # results
    s.write_uint32(0x1cb5c415)
    s.write_int32(len(users))
    for u in users:
        s.write_uint32(0x59511722)  # peerUser
        s.write_int64(u['id'])
    # chats
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    # users
    s.write_uint32(0x1cb5c415)
    s.write_int32(len(users))
    for u in users:
        _write_user(s, u)
    return s.get_bytes()


def build_contacts_resolved_peer(user=None, chat=None) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x7f077ad9)  # contacts.resolvedPeer
    if user:
        s.write_uint32(0x59511722)  # peerUser
        s.write_int64(user['id'])
    elif chat:
        s.write_uint32(0x36c6019a)  # peerChat
        s.write_int64(chat['id'])

    # chats
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    # users
    s.write_uint32(0x1cb5c415)
    if user:
        s.write_int32(1)
        _write_user(s, user)
    else:
        s.write_int32(0)
    return s.get_bytes()


# ============================================================
# MESSAGES responses
# ============================================================

def _write_message(s: TLSerializer, msg):
    s.write_uint32(0x94345242)  # message
    flags = 0
    if msg['reply_to_id']:
        flags |= (1 << 3)
    if msg['edit_date']:
        flags |= (1 << 15)
    if msg['entities_json']:
        flags |= (1 << 7)

    s.write_int32(flags)
    s.write_int32(msg['id'])

    # from_id: peerUser
    s.write_uint32(0x59511722)
    s.write_int64(msg['sender_id'])

    # peer_id: peerUser (simplified, could be chat/channel)
    s.write_uint32(0x59511722)
    s.write_int64(msg['chat_id'])

    if flags & (1 << 3):
        s.write_uint32(0x73ec805)  # messageReplyHeader
        s.write_int32(0)  # flags
        s.write_int32(msg['reply_to_id'])

    s.write_int32(msg['date'])
    s.write_string(msg['text'] or '')

    # media: messageMediaEmpty
    s.write_uint32(0x3ded6320)

    if flags & (1 << 15):
        s.write_int32(msg['edit_date'])

    if flags & (1 << 7):
        # entities (empty vector)
        s.write_uint32(0x1cb5c415)
        s.write_int32(0)


def build_messages_messages(messages, users, chats) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x8c718e87)  # messages.messages

    # messages
    s.write_uint32(0x1cb5c415)
    s.write_int32(len(messages))
    for msg in messages:
        _write_message(s, msg)

    # chats
    s.write_uint32(0x1cb5c415)
    s.write_int32(len(chats))

    # users
    s.write_uint32(0x1cb5c415)
    s.write_int32(len(users))
    for u in users:
        _write_user(s, u)

    return s.get_bytes()


def build_messages_dialogs(dialogs, messages, users, chats) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x15ba6c40)  # messages.dialogs

    # dialogs
    s.write_uint32(0x1cb5c415)
    s.write_int32(len(dialogs))
    for d in dialogs:
        s.write_uint32(0xd58a08c6)  # dialog
        s.write_int32(0)  # flags
        if d['peer_type'] == 'user':
            s.write_uint32(0x59511722)  # peerUser
            s.write_int64(d['peer_id'])
        else:
            s.write_uint32(0x36c6019a)  # peerChat
            s.write_int64(d['peer_id'])
        s.write_int32(d['top_message_id'] or 0)
        s.write_int32(d['read_inbox_max_id'] or 0)
        s.write_int32(d['read_outbox_max_id'] or 0)
        s.write_int32(d['unread_count'] or 0)
        s.write_int32(0)  # unread_mentions_count
        s.write_int32(0)  # unread_reactions_count
        # notifySettings
        s.write_uint32(0xaf509d20)
        s.write_int32(0)

    # messages
    s.write_uint32(0x1cb5c415)
    s.write_int32(len(messages))
    for msg in messages:
        _write_message(s, msg)

    # chats
    s.write_uint32(0x1cb5c415)
    s.write_int32(len(chats))

    # users
    s.write_uint32(0x1cb5c415)
    s.write_int32(len(users))
    for u in users:
        _write_user(s, u)

    return s.get_bytes()


def build_updates_short_sent_message(msg, pts) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x9015e101)  # updateShortSentMessage
    s.write_int32(0)  # flags
    s.write_int32(msg['id'])
    s.write_int32(pts)
    s.write_int32(1)  # pts_count
    s.write_int32(msg['date'])
    # media: messageMediaEmpty
    s.write_uint32(0x3ded6320)
    # entities: empty vector
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    return s.get_bytes()


def build_affected_messages(pts: int, count: int) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x84d19185)  # messages.affectedMessages
    s.write_int32(pts)
    s.write_int32(count)  # pts_count
    return s.get_bytes()


def build_vector_received_messages() -> bytes:
    s = TLSerializer()
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    return s.get_bytes()


def build_peer_dialogs() -> bytes:
    s = TLSerializer()
    s.write_uint32(0x3407e51b)  # messages.peerDialogs
    s.write_uint32(0x1cb5c415)  # dialogs
    s.write_int32(0)
    s.write_uint32(0x1cb5c415)  # messages
    s.write_int32(0)
    s.write_uint32(0x1cb5c415)  # chats
    s.write_int32(0)
    s.write_uint32(0x1cb5c415)  # users
    s.write_int32(0)
    # state
    s.write_uint32(0xa56c2a3e)
    s.write_int32(0)  # pts
    s.write_int32(0)  # qts
    s.write_int32(int(time.time()))  # date
    s.write_int32(0)  # seq
    s.write_int32(0)  # unread_count
    return s.get_bytes()


# ============================================================
# UPDATES responses
# ============================================================

def build_updates_empty() -> bytes:
    s = TLSerializer()
    s.write_uint32(0xe317af7e)  # updates (updatesTooLong simplified)
    return s.get_bytes()


def build_updates_state(pts, qts, date, seq) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xa56c2a3e)  # updates.state
    s.write_int32(pts)
    s.write_int32(qts)
    s.write_int32(date)
    s.write_int32(seq)
    s.write_int32(0)  # unread_count
    return s.get_bytes()


def build_updates_difference_empty() -> bytes:
    s = TLSerializer()
    s.write_uint32(0x5d75a138)  # updates.differenceEmpty
    s.write_int32(int(time.time()))  # date
    s.write_int32(0)  # seq
    return s.get_bytes()


def build_updates_channel_difference_empty() -> bytes:
    s = TLSerializer()
    s.write_uint32(0x3e11affb)  # updates.channelDifferenceEmpty
    s.write_int32(1)  # flags (final)
    s.write_int32(0)  # pts
    s.write_int32(300)  # timeout
    return s.get_bytes()


# ============================================================
# HELP/CONFIG responses
# ============================================================

def build_config() -> bytes:
    s = TLSerializer()
    s.write_uint32(0xcc1a241e)  # config
    s.write_int32(0)  # flags
    s.write_int32(int(time.time()))  # date
    s.write_int32(0)  # expires
    s.write_bool(False)  # test_mode
    s.write_int32(1)  # this_dc

    # dc_options vector
    s.write_uint32(0x1cb5c415)
    s.write_int32(1)
    # dcOption
    s.write_uint32(0x18b7a10d)  # dcOption
    s.write_int32(0)  # flags
    s.write_int32(1)  # id
    s.write_string("45.90.99.234")  # ip_address
    s.write_int32(443)  # port

    s.write_string("TEST")  # dc_txt_domain_name
    s.write_int32(100)  # chat_size_max
    s.write_int32(200000)  # megagroup_size_max
    s.write_int32(100)  # forwarded_count_max
    s.write_int32(200)  # online_update_period_ms
    s.write_int32(30)  # offline_blur_timeout_ms
    s.write_int32(120)  # offline_idle_timeout_ms
    s.write_int32(20)  # online_cloud_timeout_ms
    s.write_int32(5)  # notify_cloud_delay_ms
    s.write_int32(3)  # notify_default_delay_ms
    s.write_int32(0)  # push_chat_period_ms
    s.write_int32(0)  # push_chat_limit
    s.write_int32(100)  # edit_time_limit
    s.write_int32(86400)  # revoke_time_limit
    s.write_int32(86400)  # revoke_pm_time_limit
    s.write_int32(10)  # rating_e_decay
    s.write_int32(200)  # stickers_recent_limit
    s.write_int32(5)  # channels_read_media_period
    s.write_int32(2)  # tmp_sessions (optional, skipping)
    s.write_int32(100)  # call_receive_timeout_ms
    s.write_int32(60)  # call_ring_timeout_ms
    s.write_int32(120)  # call_connect_timeout_ms
    s.write_int32(30)  # call_packet_timeout_ms
    s.write_string("https://t.me/")  # me_url_prefix
    s.write_int32(4096)  # caption_length_max
    s.write_int32(4096)  # message_length_max
    s.write_int32(2 * 1024 * 1024 * 1024)  # webfile_dc_id -> actually max upload size

    return s.get_bytes()


def build_nearest_dc() -> bytes:
    s = TLSerializer()
    s.write_uint32(0x8e1a1775)  # nearestDc
    s.write_string("US")  # country
    s.write_int32(1)  # this_dc
    s.write_int32(1)  # nearest_dc
    return s.get_bytes()


def build_no_app_update() -> bytes:
    s = TLSerializer()
    s.write_uint32(0xc45a6536)  # help.noAppUpdate
    return s.get_bytes()


def build_cdn_config() -> bytes:
    s = TLSerializer()
    s.write_uint32(0x5725e40a)  # cdnConfig
    s.write_uint32(0x1cb5c415)  # public_keys vector
    s.write_int32(0)
    return s.get_bytes()


def build_app_config() -> bytes:
    s = TLSerializer()
    s.write_uint32(0xdd18782e)  # help.appConfig
    s.write_int32(0)  # hash
    # config: jsonObject
    s.write_uint32(0x99c1d49d)  # jsonObject
    s.write_uint32(0x1cb5c415)  # vector
    s.write_int32(0)
    return s.get_bytes()


def build_terms_of_service() -> bytes:
    s = TLSerializer()
    s.write_uint32(0xe3309f7f)  # help.termsOfServiceUpdateEmpty
    s.write_int32(int(time.time()) + 86400)  # expires
    return s.get_bytes()


def build_countries_list() -> bytes:
    s = TLSerializer()
    s.write_uint32(0x93cc1f32)  # help.countriesListNotModified
    return s.get_bytes()


# ============================================================
# ACCOUNT responses
# ============================================================

def build_account_password(has_password=False) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x957b50fb)  # account.password
    s.write_int32(0)  # flags (no password set)
    s.write_bytes(os.urandom(8))  # new_algo: passwordKdfAlgoUnknown
    s.write_bytes(os.urandom(8))  # new_secure_algo
    s.write_bytes(os.urandom(32))  # secure_random
    return s.get_bytes()


def build_account_authorizations(ctx) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x4bff8ea0)  # account.authorizations
    s.write_int32(7 * 86400)  # authorization_ttl_days

    s.write_uint32(0x1cb5c415)  # vector
    s.write_int32(1)

    # authorization
    s.write_uint32(0xad01d61d)
    s.write_int32(0)  # flags
    s.write_int64(0)  # hash
    s.write_int32(0)  # device_model_id... simplified
    s.write_string("Custom Server")  # platform
    s.write_string("Android")  # system_version
    s.write_int32(0)  # api_id
    s.write_string("Telegram")  # app_name
    s.write_string("1.0")  # app_version
    s.write_int32(int(time.time()))  # date_created
    s.write_int32(int(time.time()))  # date_active
    s.write_string("")  # ip
    s.write_string("")  # country

    return s.get_bytes()


def build_account_privacy_rules() -> bytes:
    s = TLSerializer()
    s.write_uint32(0x50a04e45)  # account.privacyRules
    s.write_uint32(0x1cb5c415)  # rules
    s.write_int32(1)
    s.write_uint32(0xfffe1bac)  # privacyValueAllowAll
    s.write_uint32(0x1cb5c415)  # chats
    s.write_int32(0)
    s.write_uint32(0x1cb5c415)  # users
    s.write_int32(0)
    return s.get_bytes()


def build_wall_papers() -> bytes:
    s = TLSerializer()
    s.write_uint32(0x1c199571)  # account.wallPapersNotModified
    return s.get_bytes()


# ============================================================
# CHAT responses
# ============================================================

def build_messages_chats(chats) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x64ff9fd5)  # messages.chats
    s.write_uint32(0x1cb5c415)
    s.write_int32(len(chats))
    return s.get_bytes()


def build_messages_chat_full(chat, members, users) -> bytes:
    s = TLSerializer()
    s.write_uint32(0xe5d7d19c)  # messages.chatFull
    # full_chat
    s.write_uint32(0xc9d31138)  # chatFull
    s.write_int32(0)  # flags
    s.write_int64(chat['id'])
    s.write_string(chat['description'] or '')
    # participants
    s.write_uint32(0x3cbc93f8)  # chatParticipants
    s.write_int64(chat['id'])
    s.write_uint32(0x1cb5c415)  # vector
    s.write_int32(len(members))
    for m in members:
        s.write_uint32(0xc02d4007)  # chatParticipant
        s.write_int64(m['user_id'])
        s.write_int64(chat['creator_id'] or 0)
        s.write_int32(m['joined_at'] or 0)
    s.write_int32(0)  # version

    # notifySettings
    s.write_uint32(0xaf509d20)
    s.write_int32(0)

    # chats
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    # users
    s.write_uint32(0x1cb5c415)
    s.write_int32(len(users))
    for u in users:
        _write_user(s, u)

    return s.get_bytes()


def build_messages_chat_full_empty() -> bytes:
    return build_messages_chat_full({'id': 0, 'description': '', 'creator_id': 0}, [], [])


def build_channels_participants() -> bytes:
    s = TLSerializer()
    s.write_uint32(0x9ab0feaf)  # channels.channelParticipants
    s.write_int32(0)  # count
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    return s.get_bytes()


# ============================================================
# UPLOAD responses
# ============================================================

def build_upload_file(data: bytes, mime_type: str) -> bytes:
    s = TLSerializer()
    s.write_uint32(0x96a18d5)  # upload.file
    # type: storage.fileUnknown
    s.write_uint32(0xaa963b05)
    s.write_int32(0)  # mtime
    s.write_bytes(data)
    return s.get_bytes()


# ============================================================
# STICKERS responses
# ============================================================

def build_all_stickers() -> bytes:
    s = TLSerializer()
    s.write_uint32(0xcdbbcebb)  # messages.allStickersNotModified
    return s.get_bytes()


def build_sticker_set() -> bytes:
    s = TLSerializer()
    s.write_uint32(0xd3f924eb)  # messages.stickerSet
    s.write_int32(0)  # flags
    # stickerSet
    s.write_uint32(0x2dd14edc)
    s.write_int32(0)  # flags
    s.write_int64(0)  # id
    s.write_int64(0)  # access_hash
    s.write_string("")  # title
    s.write_string("")  # short_name
    s.write_int32(0)  # count
    s.write_int32(0)  # hash
    # packs
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    # keywords
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    # documents
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    return s.get_bytes()


def build_sticker_set_installed() -> bytes:
    s = TLSerializer()
    s.write_uint32(0x38641628)  # messages.stickerSetInstallResultSuccess
    return s.get_bytes()


def build_recent_stickers() -> bytes:
    s = TLSerializer()
    s.write_uint32(0xb17f890)  # messages.recentStickersNotModified
    return s.get_bytes()


def build_faved_stickers() -> bytes:
    s = TLSerializer()
    s.write_uint32(0x9e8fa6d3)  # messages.favedStickersNotModified
    return s.get_bytes()


# ============================================================
# POLLS, PHOTOS, STORIES responses
# ============================================================

def build_poll_votes() -> bytes:
    s = TLSerializer()
    s.write_uint32(0x823f649)  # messages.votesList
    s.write_int32(0)  # flags
    s.write_int32(0)  # count
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    return s.get_bytes()


def build_photos_photo() -> bytes:
    s = TLSerializer()
    s.write_uint32(0x20212ca8)  # photos.photo
    # photo
    s.write_uint32(0x2331b22d)  # photoEmpty
    s.write_int64(0)
    # users
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    return s.get_bytes()


def build_stories_all() -> bytes:
    s = TLSerializer()
    s.write_uint32(0x63c3dd0a)  # stories.allStoriesNotModified
    s.write_int32(0)  # flags
    s.write_string("")  # state
    return s.get_bytes()


def build_stories_peer() -> bytes:
    s = TLSerializer()
    s.write_uint32(0xcae68768)  # stories.peerStories
    s.write_int32(0)  # flags
    # peerStories
    s.write_uint32(0x9a35e999)
    s.write_int32(0)  # flags
    s.write_uint32(0x59511722)  # peerUser
    s.write_int64(0)
    s.write_uint32(0x1cb5c415)  # stories
    s.write_int32(0)
    # chats
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    # users
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    return s.get_bytes()


def build_stories_views() -> bytes:
    s = TLSerializer()
    s.write_uint32(0xde9eed1d)  # stories.storyViewsList
    s.write_int32(0)  # flags
    s.write_int32(0)  # count
    s.write_int32(0)  # views_count
    s.write_int32(0)  # forwards_count
    s.write_int32(0)  # reactions_count
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    s.write_uint32(0x1cb5c415)
    s.write_int32(0)
    return s.get_bytes()


# ============================================================
# LANGPACK responses
# ============================================================

def build_langpack_languages() -> bytes:
    s = TLSerializer()
    s.write_uint32(0x1cb5c415)  # vector
    s.write_int32(1)
    # langPackLanguage
    s.write_uint32(0xeeca5ce3)
    s.write_int32(1)  # flags (official)
    s.write_string("en")
    s.write_string("English")
    s.write_string("English")
    s.write_string("")  # plural_code
    s.write_int32(0)  # strings_count
    s.write_int32(0)  # translated_count
    s.write_string("")  # translations_url
    return s.get_bytes()


def build_langpack_difference() -> bytes:
    s = TLSerializer()
    s.write_uint32(0xf385c1f6)  # langPackDifference
    s.write_string("en")
    s.write_int32(0)  # from_version
    s.write_int32(0)  # version
    s.write_uint32(0x1cb5c415)  # strings
    s.write_int32(0)
    return s.get_bytes()


def build_langpack_strings() -> bytes:
    s = TLSerializer()
    s.write_uint32(0x1cb5c415)  # vector
    s.write_int32(0)
    return s.get_bytes()
