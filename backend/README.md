# Custom MTProto Server

A full MTProto protocol server that replaces Telegram's official backend infrastructure. The Telegram Android client connects to this server instead of Telegram's datacenters.

## Architecture

```
Telegram Android Client
        │
        │ MTProto (TCP, port 443)
        ▼
┌──────────────────────┐
│  TCP Transport Layer │  (Abridged/Intermediate/Full)
├──────────────────────┤
│  MTProto Encryption  │  (AES-IGE, SHA256, MTProto 2.0)
├──────────────────────┤
│  DH Key Exchange     │  (RSA + DH handshake)
├──────────────────────┤
│  RPC Dispatcher      │  (TL constructor routing)
├──────────────────────┤
│  API Handlers        │  (auth, messages, contacts, etc.)
├──────────────────────┤
│  SQLite Database     │  (users, chats, messages, files)
└──────────────────────┘
```

## Features

- **Full MTProto 2.0 protocol support**: DH key exchange, AES-IGE encryption, TL serialization
- **Authentication**: auth.sendCode, auth.signIn, auth.signUp, 2FA
- **Messages**: send, receive, edit, delete, forward, search, pin
- **Media**: file upload/download (photos, videos, documents, voice)
- **Contacts**: import, search, block/unblock
- **Chats**: private chats, groups, supergroups, channels
- **User profiles**: update name, username, bio, status
- **Updates**: state management, difference sync
- **Stories**: create, view, delete
- **Stickers**: packs, recent, faved
- **Reactions**: on messages
- **Polls**: create, vote
- **Config**: dcOptions, help.getConfig, nearestDc

## Quick Start

### Prerequisites
- Python 3.10+
- pip

### Install & Run

```bash
cd backend
pip install -r requirements.txt
python main.py --port 443
```

### Docker

```bash
cd backend
docker build -t mtproto-server .
docker run -d -p 443:443 --name mtproto mtproto-server
```

## Auth Flow

When a user opens the app:
1. Client connects to 45.90.99.234:443 via TCP
2. MTProto handshake (DH key exchange) establishes auth_key
3. Client calls `auth.sendCode(phone_number)` → server generates 5-digit code (logged to console)
4. Client calls `auth.signIn(phone, code)` → server authenticates and returns user info
5. All subsequent requests use the encrypted auth_key

## Server Files

| File | Description |
|------|-------------|
| `main.py` | Entry point |
| `mtproto_server/tcp_server.py` | TCP server, transport detection, connection handling |
| `mtproto_server/handshake.py` | DH key exchange (req_pq_multi → resPQ → server_DH_params → dh_gen_ok) |
| `mtproto_server/crypto.py` | RSA, AES-IGE, SHA, DH prime, auth_key derivation |
| `mtproto_server/message_processor.py` | MTProto message framing, encrypt/decrypt |
| `mtproto_server/tl_serialization.py` | TL binary serialization (int, long, string, bytes, vector) |
| `mtproto_server/tl_constructors.py` | TL constructor IDs for all API methods |
| `mtproto_server/rpc_handlers.py` | RPC request handlers for all Telegram API methods |
| `mtproto_server/tl_responses.py` | TL response builders for all response types |
| `mtproto_server/database.py` | SQLite database schema and helpers |

## Configuration

The server generates an RSA key pair on first run (`server_key.pem`). This key must match what the client uses during handshake. The client's `Handshake.cpp` must be updated with the server's public key.

## Database

SQLite database (`messenger.db`) stores:
- Users, auth keys, sessions
- Chats, chat members
- Messages, media, reactions
- Contacts, dialogs
- Files, stickers, polls
- Stories, updates state
