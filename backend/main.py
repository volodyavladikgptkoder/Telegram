#!/usr/bin/env python3
"""
Custom MTProto server — drop-in replacement for Telegram's backend.
Accepts connections from Telegram Android client and handles all RPC methods.

Usage:
    python main.py [--host 0.0.0.0] [--port 443]
"""

import asyncio
import argparse
import logging
import sys
import os

# Add parent to path
sys.path.insert(0, os.path.dirname(__file__))

from mtproto_server.tcp_server import start_server


def main():
    parser = argparse.ArgumentParser(description='Custom MTProto Server')
    parser.add_argument('--host', default='0.0.0.0', help='Bind address (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=443, help='Port (default: 443)')
    parser.add_argument('--log-level', default='INFO', help='Log level (default: INFO)')
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    print(f"""
╔══════════════════════════════════════════╗
║     Custom MTProto Server v1.0           ║
║     Listening on {args.host}:{args.port:<5}            ║
╚══════════════════════════════════════════╝
    """)

    asyncio.run(start_server(args.host, args.port))


if __name__ == '__main__':
    main()
