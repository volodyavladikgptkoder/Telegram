"""
Database layer for the MTProto server.
Uses SQLite for storage of users, messages, chats, contacts, etc.
"""

import sqlite3
import time
import os
import threading
import json
import logging

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'messenger.db')

_local = threading.local()


def get_db() -> sqlite3.Connection:
    if not hasattr(_local, 'conn') or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phone TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE,
        first_name TEXT NOT NULL DEFAULT '',
        last_name TEXT NOT NULL DEFAULT '',
        bio TEXT,
        avatar_path TEXT,
        password_hash TEXT,
        two_fa_enabled INTEGER DEFAULT 0,
        is_online INTEGER DEFAULT 0,
        last_seen INTEGER DEFAULT 0,
        is_premium INTEGER DEFAULT 0,
        is_bot INTEGER DEFAULT 0,
        phone_code TEXT,
        phone_code_expires INTEGER,
        auth_key_id INTEGER,
        access_hash INTEGER DEFAULT 0,
        created_at INTEGER DEFAULT 0,
        status_text TEXT,
        language_code TEXT DEFAULT 'en'
    );

    CREATE TABLE IF NOT EXISTS auth_keys (
        auth_key_id INTEGER PRIMARY KEY,
        auth_key BLOB NOT NULL,
        user_id INTEGER,
        session_id INTEGER,
        server_salt INTEGER DEFAULT 0,
        is_temp INTEGER DEFAULT 0,
        expires_at INTEGER DEFAULT 0,
        created_at INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS sessions (
        session_id INTEGER PRIMARY KEY,
        auth_key_id INTEGER NOT NULL,
        user_id INTEGER,
        layer INTEGER DEFAULT 0,
        api_id INTEGER DEFAULT 0,
        device_model TEXT,
        system_version TEXT,
        app_version TEXT,
        lang_code TEXT,
        system_lang_code TEXT,
        seq_no INTEGER DEFAULT 0,
        created_at INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_type TEXT NOT NULL DEFAULT 'private',
        title TEXT,
        username TEXT UNIQUE,
        description TEXT,
        avatar_path TEXT,
        invite_link TEXT,
        is_public INTEGER DEFAULT 0,
        creator_id INTEGER,
        member_count INTEGER DEFAULT 0,
        pinned_message_id INTEGER,
        access_hash INTEGER DEFAULT 0,
        created_at INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS chat_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        role TEXT DEFAULT 'member',
        joined_at INTEGER DEFAULT 0,
        can_send_messages INTEGER DEFAULT 1,
        can_send_media INTEGER DEFAULT 1,
        can_pin_messages INTEGER DEFAULT 0,
        can_delete_messages INTEGER DEFAULT 0,
        can_ban_users INTEGER DEFAULT 0,
        can_change_info INTEGER DEFAULT 0,
        can_manage_chat INTEGER DEFAULT 0,
        is_muted INTEGER DEFAULT 0,
        UNIQUE(chat_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        sender_id INTEGER NOT NULL,
        text TEXT,
        reply_to_id INTEGER,
        forward_from_id INTEGER,
        forward_from_chat_id INTEGER,
        forward_from_message_id INTEGER,
        edit_date INTEGER,
        is_pinned INTEGER DEFAULT 0,
        is_outgoing INTEGER DEFAULT 0,
        is_deleted INTEGER DEFAULT 0,
        date INTEGER DEFAULT 0,
        views INTEGER DEFAULT 0,
        message_type TEXT DEFAULT 'text',
        entities_json TEXT,
        group_id INTEGER,
        media_json TEXT,
        pts INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        contact_user_id INTEGER NOT NULL,
        is_mutual INTEGER DEFAULT 0,
        is_blocked INTEGER DEFAULT 0,
        added_at INTEGER DEFAULT 0,
        UNIQUE(user_id, contact_user_id)
    );

    CREATE TABLE IF NOT EXISTS dialogs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        peer_type TEXT NOT NULL,
        peer_id INTEGER NOT NULL,
        top_message_id INTEGER DEFAULT 0,
        unread_count INTEGER DEFAULT 0,
        read_inbox_max_id INTEGER DEFAULT 0,
        read_outbox_max_id INTEGER DEFAULT 0,
        is_pinned INTEGER DEFAULT 0,
        folder_id INTEGER DEFAULT 0,
        pts INTEGER DEFAULT 0,
        UNIQUE(user_id, peer_type, peer_id)
    );

    CREATE TABLE IF NOT EXISTS stories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        media_type TEXT NOT NULL,
        media_path TEXT NOT NULL,
        caption TEXT,
        privacy TEXT DEFAULT 'everyone',
        view_count INTEGER DEFAULT 0,
        expires_at INTEGER NOT NULL,
        created_at INTEGER DEFAULT 0,
        is_deleted INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS reactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        emoji TEXT NOT NULL,
        created_at INTEGER DEFAULT 0,
        UNIQUE(message_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER UNIQUE,
        access_hash INTEGER DEFAULT 0,
        file_path TEXT NOT NULL,
        file_name TEXT,
        file_size INTEGER DEFAULT 0,
        mime_type TEXT,
        media_type TEXT,
        width INTEGER,
        height INTEGER,
        duration REAL,
        thumb_path TEXT,
        dc_id INTEGER DEFAULT 1,
        created_at INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS file_parts (
        file_id INTEGER NOT NULL,
        part_num INTEGER NOT NULL,
        data BLOB NOT NULL,
        PRIMARY KEY (file_id, part_num)
    );

    CREATE TABLE IF NOT EXISTS sticker_sets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        access_hash INTEGER DEFAULT 0,
        name TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        count INTEGER DEFAULT 0,
        is_animated INTEGER DEFAULT 0,
        is_video INTEGER DEFAULT 0,
        thumb_path TEXT,
        created_at INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS stickers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        set_id INTEGER NOT NULL,
        emoji TEXT,
        file_path TEXT NOT NULL,
        width INTEGER DEFAULT 512,
        height INTEGER DEFAULT 512,
        is_animated INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS polls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id INTEGER NOT NULL,
        question TEXT NOT NULL,
        is_closed INTEGER DEFAULT 0,
        is_anonymous INTEGER DEFAULT 1,
        is_multiple INTEGER DEFAULT 0,
        is_quiz INTEGER DEFAULT 0,
        correct_option INTEGER
    );

    CREATE TABLE IF NOT EXISTS poll_options (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        poll_id INTEGER NOT NULL,
        option_text TEXT NOT NULL,
        option_data BLOB NOT NULL
    );

    CREATE TABLE IF NOT EXISTS poll_votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        poll_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        option_id INTEGER NOT NULL,
        UNIQUE(poll_id, user_id, option_id)
    );

    CREATE TABLE IF NOT EXISTS updates_state (
        user_id INTEGER PRIMARY KEY,
        pts INTEGER DEFAULT 0,
        qts INTEGER DEFAULT 0,
        date INTEGER DEFAULT 0,
        seq INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS phone_calls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        access_hash INTEGER DEFAULT 0,
        caller_id INTEGER NOT NULL,
        callee_id INTEGER NOT NULL,
        g_a_hash BLOB,
        g_a BLOB,
        g_b BLOB,
        protocol_json TEXT,
        state TEXT DEFAULT 'requested',
        reason TEXT,
        duration INTEGER DEFAULT 0,
        is_video INTEGER DEFAULT 0,
        rating INTEGER,
        comment TEXT,
        created_at INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS encrypted_chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        access_hash INTEGER DEFAULT 0,
        creator_id INTEGER NOT NULL,
        participant_id INTEGER NOT NULL,
        g_a BLOB,
        g_b BLOB,
        key_fingerprint INTEGER DEFAULT 0,
        state TEXT DEFAULT 'requested',
        created_at INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS drafts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        peer_type TEXT NOT NULL,
        peer_id INTEGER NOT NULL,
        message TEXT,
        reply_to_msg_id INTEGER,
        entities_json TEXT,
        date INTEGER DEFAULT 0,
        UNIQUE(user_id, peer_type, peer_id)
    );

    CREATE TABLE IF NOT EXISTS dialog_filters (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        emoticon TEXT,
        flags INTEGER DEFAULT 0,
        include_peers_json TEXT DEFAULT '[]',
        exclude_peers_json TEXT DEFAULT '[]',
        pinned_peers_json TEXT DEFAULT '[]',
        order_pos INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS scheduled_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        sender_id INTEGER NOT NULL,
        text TEXT,
        media_json TEXT,
        schedule_date INTEGER NOT NULL,
        reply_to_id INTEGER,
        entities_json TEXT,
        is_sent INTEGER DEFAULT 0,
        created_at INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS forum_topics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        channel_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        icon_color INTEGER DEFAULT 0,
        icon_emoji_id INTEGER DEFAULT 0,
        creator_id INTEGER NOT NULL,
        top_message_id INTEGER DEFAULT 0,
        unread_count INTEGER DEFAULT 0,
        is_pinned INTEGER DEFAULT 0,
        is_closed INTEGER DEFAULT 0,
        created_at INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS group_calls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        access_hash INTEGER DEFAULT 0,
        chat_id INTEGER NOT NULL,
        title TEXT,
        creator_id INTEGER NOT NULL,
        participant_count INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        schedule_date INTEGER,
        created_at INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS group_call_participants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        call_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        is_muted INTEGER DEFAULT 0,
        is_video INTEGER DEFAULT 0,
        joined_at INTEGER DEFAULT 0,
        UNIQUE(call_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS account_settings (
        user_id INTEGER PRIMARY KEY,
        account_ttl_days INTEGER DEFAULT 365,
        global_privacy_json TEXT DEFAULT '{}'
    );

    CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id, date);
    CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
    CREATE INDEX IF NOT EXISTS idx_dialogs_user ON dialogs(user_id);
    CREATE INDEX IF NOT EXISTS idx_contacts_user ON contacts(user_id);
    CREATE INDEX IF NOT EXISTS idx_chat_members_chat ON chat_members(chat_id);
    CREATE INDEX IF NOT EXISTS idx_chat_members_user ON chat_members(user_id);
    CREATE INDEX IF NOT EXISTS idx_auth_keys_user ON auth_keys(user_id);
    CREATE INDEX IF NOT EXISTS idx_drafts_user ON drafts(user_id);
    CREATE INDEX IF NOT EXISTS idx_scheduled_date ON scheduled_messages(schedule_date);
    CREATE INDEX IF NOT EXISTS idx_forum_topics_channel ON forum_topics(channel_id);
    """)
    conn.commit()
    logger.info(f"Database initialized at {DB_PATH}")


def get_next_pts(user_id: int) -> int:
    conn = get_db()
    row = conn.execute("SELECT pts FROM updates_state WHERE user_id = ?", (user_id,)).fetchone()
    if row:
        pts = row['pts'] + 1
        conn.execute("UPDATE updates_state SET pts = ? WHERE user_id = ?", (pts, user_id))
    else:
        pts = 1
        conn.execute("INSERT INTO updates_state (user_id, pts, date) VALUES (?, ?, ?)", (user_id, pts, int(time.time())))
    conn.commit()
    return pts
