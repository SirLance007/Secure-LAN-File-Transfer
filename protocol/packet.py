"""
Network Packet Serialization and Framing Layer
Ensures reliable TCP stream framing using length-prefixed headers.
"""

import json
import socket
import struct
from typing import Tuple, Any, Union

import config
from protocol.constants import (
    HEADER_FORMAT,
    HEADER_SIZE,
    OPCODE_NAMES,
    OP_ERR_GENERIC
)


class ProtocolError(Exception):
    """Base exception for protocol violations."""
    pass


class ConnectionClosedError(ProtocolError):
    """Raised when the remote peer gracefully closes the connection."""
    pass


class CorruptedPacketError(ProtocolError):
    """Raised when header magic bytes or framing data is invalid."""
    pass


def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """
    Guarantees reading exactly num_bytes from a TCP stream socket.
    Handles TCP fragmentation and partial chunk arrivals.
    """
    buffer = bytearray()
    while len(buffer) < num_bytes:
        remaining = num_bytes - len(buffer)
        try:
            chunk = sock.recv(remaining)
        except (socket.timeout, BlockingIOError) as e:
            raise e
        except OSError as e:
            raise ConnectionClosedError(f"Socket read error: {e}") from e

        if not chunk:
            if len(buffer) == 0:
                raise ConnectionClosedError("Remote endpoint closed connection.")
            else:
                raise ConnectionClosedError(
                    f"Unexpected EOF while reading packet: expected {num_bytes} bytes, received {len(buffer)}"
                )
        buffer.extend(chunk)

    return bytes(buffer)


def pack_packet(opcode: int, payload: Union[bytes, dict, list, str]) -> bytes:
    """
    Pack an opcode and payload into a formatted byte stream with header.
    JSON objects/strings are encoded as UTF-8.
    """
    if isinstance(payload, (dict, list)):
        payload_bytes = json.dumps(payload).encode("utf-8")
    elif isinstance(payload, str):
        payload_bytes = payload.encode("utf-8")
    elif isinstance(payload, bytes):
        payload_bytes = payload
    else:
        raise ValueError(f"Unsupported payload type: {type(payload)}")

    length = len(payload_bytes)
    if length > config.MAX_PACKET_SIZE:
        raise ValueError(f"Packet payload size ({length} bytes) exceeds limit ({config.MAX_PACKET_SIZE} bytes).")

    header = struct.pack(
        HEADER_FORMAT,
        config.MAGIC_BYTES,
        config.PROTOCOL_VERSION,
        opcode,
        length
    )

    return header + payload_bytes


def send_packet(sock: socket.socket, opcode: int, payload: Union[bytes, dict, list, str] = b"") -> None:
    """
    Pack and send a packet atomically over a connected socket.
    """
    packet_data = pack_packet(opcode, payload)
    sock.sendall(packet_data)


def recv_packet(sock: socket.socket) -> Tuple[int, Any]:
    """
    Receive and parse a complete packet from the socket.
    Returns:
        (opcode, payload) where payload is a dict/list if valid JSON, or raw bytes.
    """
    header_bytes = recv_exact(sock, HEADER_SIZE)
    magic, version, opcode, length = struct.unpack(HEADER_FORMAT, header_bytes)

    if magic != config.MAGIC_BYTES:
        raise CorruptedPacketError(f"Invalid magic bytes: expected {config.MAGIC_BYTES!r}, got {magic!r}")

    if version != config.PROTOCOL_VERSION:
        raise CorruptedPacketError(f"Unsupported protocol version: {version}")

    if length > config.MAX_PACKET_SIZE:
        raise CorruptedPacketError(f"Packet length {length} exceeds maximum allowable {config.MAX_PACKET_SIZE}")

    payload_bytes = recv_exact(sock, length) if length > 0 else b""

    # Attempt to decode as JSON if possible
    try:
        decoded_text = payload_bytes.decode("utf-8")
        payload = json.loads(decoded_text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = payload_bytes

    return opcode, payload
