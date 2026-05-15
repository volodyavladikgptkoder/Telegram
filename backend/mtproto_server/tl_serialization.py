"""
TL (Type Language) serialization/deserialization for MTProto protocol.
Handles reading/writing of basic TL types: int, long, int128, int256, string, bytes.
"""

import struct
import os


class TLSerializer:
    """Writes TL-serialized data to a byte buffer."""

    def __init__(self):
        self.buffer = bytearray()

    def write_int32(self, value: int):
        self.buffer += struct.pack('<i', value)

    def write_uint32(self, value: int):
        self.buffer += struct.pack('<I', value)

    def write_int64(self, value: int):
        self.buffer += struct.pack('<q', value)

    def write_uint64(self, value: int):
        self.buffer += struct.pack('<Q', value)

    def write_int128(self, data: bytes):
        assert len(data) == 16
        self.buffer += data

    def write_int256(self, data: bytes):
        assert len(data) == 32
        self.buffer += data

    def write_bytes(self, data: bytes):
        length = len(data)
        if length < 254:
            self.buffer += struct.pack('<B', length)
            self.buffer += data
            padding = (length + 1) % 4
            if padding:
                self.buffer += b'\x00' * (4 - padding)
        else:
            self.buffer += b'\xfe'
            self.buffer += struct.pack('<I', length)[:3]
            self.buffer += data
            padding = length % 4
            if padding:
                self.buffer += b'\x00' * (4 - padding)

    def write_string(self, value: str):
        self.write_bytes(value.encode('utf-8'))

    def write_raw(self, data: bytes):
        self.buffer += data

    def write_bool(self, value: bool):
        if value:
            self.write_uint32(0x997275b5)  # boolTrue
        else:
            self.write_uint32(0xbc799737)  # boolFalse

    def write_vector(self, items: list, write_func):
        self.write_uint32(0x1cb5c415)  # vector constructor
        self.write_int32(len(items))
        for item in items:
            write_func(self, item)

    def get_bytes(self) -> bytes:
        return bytes(self.buffer)


class TLDeserializer:
    """Reads TL-serialized data from a byte buffer."""

    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def read_int32(self) -> int:
        value = struct.unpack_from('<i', self.data, self.offset)[0]
        self.offset += 4
        return value

    def read_uint32(self) -> int:
        value = struct.unpack_from('<I', self.data, self.offset)[0]
        self.offset += 4
        return value

    def read_int64(self) -> int:
        value = struct.unpack_from('<q', self.data, self.offset)[0]
        self.offset += 8
        return value

    def read_uint64(self) -> int:
        value = struct.unpack_from('<Q', self.data, self.offset)[0]
        self.offset += 8
        return value

    def read_int128(self) -> bytes:
        data = self.data[self.offset:self.offset + 16]
        self.offset += 16
        return bytes(data)

    def read_int256(self) -> bytes:
        data = self.data[self.offset:self.offset + 32]
        self.offset += 32
        return bytes(data)

    def read_bytes(self) -> bytes:
        first_byte = self.data[self.offset]
        self.offset += 1
        if first_byte < 254:
            length = first_byte
            data = self.data[self.offset:self.offset + length]
            self.offset += length
            padding = (length + 1) % 4
            if padding:
                self.offset += 4 - padding
        else:
            length = struct.unpack_from('<I', self.data[self.offset:self.offset + 3] + b'\x00', 0)[0]
            self.offset += 3
            data = self.data[self.offset:self.offset + length]
            self.offset += length
            padding = length % 4
            if padding:
                self.offset += 4 - padding
        return bytes(data)

    def read_string(self) -> str:
        return self.read_bytes().decode('utf-8', errors='replace')

    def read_raw(self, length: int) -> bytes:
        data = self.data[self.offset:self.offset + length]
        self.offset += length
        return bytes(data)

    def read_bool(self) -> bool:
        constructor = self.read_uint32()
        return constructor == 0x997275b5

    def read_vector(self, read_func) -> list:
        constructor = self.read_uint32()
        assert constructor == 0x1cb5c415
        count = self.read_int32()
        items = []
        for _ in range(count):
            items.append(read_func(self))
        return items

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset
