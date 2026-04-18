"""Zepp OS 2021+ chunked-2021 framing + auth — shared library.

Ports the essentials of Gadgetbridge's Huami2021ChunkedEncoder,
Huami2021ChunkedDecoder and ZeppOsAuthenticationService to Python. Only the
pieces we actually need for a one-shot session from bleak on Windows.
"""

from __future__ import annotations

import asyncio
import struct
import zlib
from typing import Awaitable, Callable, Optional

from bleak import BleakClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import huami_ecdh


# --- chars / constants ----------------------------------------------------

CHAR_CHUNKED_WRITE = "00000016-0000-3512-2118-0009af100700"
CHAR_CHUNKED_READ  = "00000017-0000-3512-2118-0009af100700"

ENDPOINT_AUTH = 0x0082

RESPONSE = 0x10
SUCCESS = 0x01
CMD_PUB_KEY = 0x04
CMD_SESSION_KEY = 0x05


# --- AES helpers ----------------------------------------------------------

def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    assert len(key) == 16 and len(data) % 16 == 0
    return Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(data)


def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    assert len(key) == 16 and len(data) % 16 == 0
    return Cipher(algorithms.AES(key), modes.ECB()).decryptor().update(data)


def _message_key(session_key: bytes, handle: int) -> bytes:
    b = handle & 0xFF
    return bytes(x ^ b for x in session_key)


# --- session state --------------------------------------------------------

class Session:
    """Shared state for a connected + authenticated Zepp OS link."""

    def __init__(self, mtu: int):
        self.mtu = max(mtu, 23)
        self.session_key: Optional[bytes] = None
        self.encrypted_seq: int = 0
        self.write_handle: int = 0  # host->device

    def next_handle(self) -> int:
        self.write_handle = (self.write_handle + 1) & 0xFF
        return self.write_handle


# --- encoder --------------------------------------------------------------

HEADER_FIRST_EXT = 11   # 0x03 flags 0x00 handle count len(4) type(2)
HEADER_CONT_EXT = 5     # 0x03 flags 0x00 handle count


def encode_chunks(session: Session, endpoint: int, data: bytes,
                  encrypt: bool) -> list[bytes]:
    """Produce the raw writes for one host->device message.

    Matches Huami2021ChunkedEncoder.write with extended_flags=True.
    """
    handle = session.next_handle()

    if encrypt:
        if session.session_key is None:
            raise RuntimeError("cannot encrypt without session key")
        msg_key = _message_key(session.session_key, handle)
        length = len(data)
        enc_len = length + 8
        overflow = enc_len % 16
        if overflow:
            enc_len += 16 - overflow

        pt = bytearray(enc_len)
        pt[0:length] = data
        seqnr = session.encrypted_seq
        struct.pack_into("<I", pt, length, seqnr)
        session.encrypted_seq = (seqnr + 1) & 0xFFFFFFFF
        crc = zlib.crc32(bytes(pt[:length + 4])) & 0xFFFFFFFF
        struct.pack_into("<I", pt, length + 4, crc)
        payload = aes_ecb_encrypt(msg_key, bytes(pt))
    else:
        length = len(data)
        payload = data

    chunks: list[bytes] = []
    remaining = len(payload)
    offset = 0
    count = 0

    while remaining > 0:
        first = count == 0
        hdr = HEADER_FIRST_EXT if first else HEADER_CONT_EXT
        max_chunk = (session.mtu - 3) - hdr
        take = min(remaining, max_chunk)

        flags = 0
        if first:
            flags |= 0x01
        if remaining <= max_chunk:
            flags |= 0x02  # last
            flags |= 0x04  # needs ack
        if encrypt:
            flags |= 0x08

        buf = bytearray(hdr + take)
        buf[0] = 0x03
        buf[1] = flags
        buf[2] = 0x00
        buf[3] = handle
        buf[4] = count
        if first:
            struct.pack_into("<I", buf, 5, length)
            struct.pack_into("<H", buf, 9, endpoint)
        buf[hdr:] = payload[offset:offset + take]

        chunks.append(bytes(buf))
        offset += take
        remaining -= take
        count += 1

    return chunks


# --- decoder --------------------------------------------------------------

class ChunkedDecoder:
    """Device->host chunked reassembly + (optional) decryption."""

    def __init__(self, session: Session):
        self.session = session
        self._reset()

    def _reset(self):
        self.handle: Optional[int] = None
        self.type: int = 0
        self.length: int = 0
        self.buf = bytearray()
        self.encrypted = False

    def feed(self, data: bytes) -> Optional[tuple[int, bytes]]:
        if not data or data[0] != 0x03:
            return None
        i = 1
        flags = data[i]; i += 1
        encrypted = bool(flags & 0x08)
        first = bool(flags & 0x01)
        last = bool(flags & 0x02)
        i += 1  # extended flags zero byte
        handle = data[i]; i += 1
        count = data[i]; i += 1

        if self.handle is not None and self.handle != handle:
            # device interleaved a different transfer; drop current
            self._reset()

        if first:
            full_length = struct.unpack_from("<I", data, i)[0]
            i += 4
            self.length = full_length
            if encrypted:
                enc_len = full_length + 8
                overflow = enc_len % 16
                if overflow:
                    enc_len += 16 - overflow
                buf_size = enc_len
            else:
                buf_size = full_length
            self.buf = bytearray()
            self.type = struct.unpack_from("<H", data, i)[0]
            i += 2
            self.handle = handle
            self.encrypted = encrypted

        self.buf.extend(data[i:])

        if not last:
            return None

        if self.encrypted:
            if self.session.session_key is None:
                self._reset()
                return None
            msg_key = _message_key(self.session.session_key, self.handle)
            try:
                pt = aes_ecb_decrypt(msg_key, bytes(self.buf))
            except Exception:
                self._reset()
                return None
            payload = pt[: self.length]
        else:
            payload = bytes(self.buf[: self.length])

        result = (self.type, payload)
        self._reset()
        return result


# --- auth orchestration ---------------------------------------------------

async def connect_and_auth(mac: str, auth_key: bytes,
                           on_raw_read: Optional[Callable[[str, bytes], None]] = None
                           ) -> tuple[BleakClient, Session, asyncio.Queue]:
    """Connect, subscribe to chunked-read, run the ECDH handshake.

    Returns the live client, an authenticated Session, and a queue that
    yields (endpoint_type, payload) tuples from the chunked-read channel
    (decrypted if applicable).
    """
    client = BleakClient(mac)
    await client.connect()
    session = Session(mtu=client.mtu_size or 23)
    decoder = ChunkedDecoder(session)
    queue: asyncio.Queue[tuple[int, bytes]] = asyncio.Queue()

    def on_read(_sender, data: bytearray):
        if on_raw_read:
            on_raw_read("chunked-read", bytes(data))
        result = decoder.feed(bytes(data))
        if result is not None:
            queue.put_nowait(result)

    await client.start_notify(CHAR_CHUNKED_READ, on_read)

    # Stage 1: send public key
    priv, pub = huami_ecdh.generate_keypair()
    pub_cmd = bytes([CMD_PUB_KEY, 0x02, 0x00, 0x02]) + pub
    for chunk in encode_chunks(session, ENDPOINT_AUTH, pub_cmd, encrypt=False):
        await client.write_gatt_char(CHAR_CHUNKED_WRITE, chunk, response=False)

    ep_type, payload = await asyncio.wait_for(queue.get(), timeout=10)
    if ep_type != ENDPOINT_AUTH or payload[0] != RESPONSE or payload[1] != CMD_PUB_KEY:
        raise RuntimeError(f"unexpected pub key reply: {payload.hex()}")
    if payload[2] != SUCCESS:
        raise RuntimeError(f"pub key rejected, status 0x{payload[2]:02x}")

    remote_random = payload[3:19]
    remote_pub = payload[19:19 + 48]
    shared_ec = huami_ecdh.generate_shared(priv, remote_pub)
    encrypted_seq = struct.unpack("<I", shared_ec[0:4])[0]
    session_key = bytes(shared_ec[i + 8] ^ auth_key[i] for i in range(16))

    session.session_key = session_key
    session.encrypted_seq = encrypted_seq

    # Stage 2: prove we can derive the session
    enc_r1 = aes_ecb_encrypt(auth_key, remote_random)
    enc_r2 = aes_ecb_encrypt(session_key, remote_random)
    session_cmd = bytes([CMD_SESSION_KEY]) + enc_r1 + enc_r2
    for chunk in encode_chunks(session, ENDPOINT_AUTH, session_cmd, encrypt=False):
        await client.write_gatt_char(CHAR_CHUNKED_WRITE, chunk, response=False)

    ep_type, payload = await asyncio.wait_for(queue.get(), timeout=10)
    if payload[0] != RESPONSE or payload[1] != CMD_SESSION_KEY:
        raise RuntimeError(f"unexpected session reply: {payload.hex()}")
    if payload[2] == 0x25:
        raise RuntimeError("wrong auth key")
    if payload[2] != SUCCESS:
        raise RuntimeError(f"session key rejected, status 0x{payload[2]:02x}")

    return client, session, queue


async def send_encrypted(client: BleakClient, session: Session,
                         endpoint: int, data: bytes) -> None:
    for chunk in encode_chunks(session, endpoint, data, encrypt=True):
        await client.write_gatt_char(CHAR_CHUNKED_WRITE, chunk, response=False)
