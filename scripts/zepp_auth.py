"""Zepp OS 2021+ BLE authentication handshake — Helio Strap / Amazfit.

Implements the ECDH-based auth flow from Gadgetbridge
`ZeppOsAuthenticationService.java`. On success prints the derived shared
session key + encrypted sequence number, which are the state needed to
decrypt/encrypt all subsequent chunked-2021 traffic.

Usage:
    python zepp_auth.py
"""

from __future__ import annotations

import asyncio
import struct
from typing import Optional

from bleak import BleakClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import huami_ecdh


# --- config ---------------------------------------------------------------

MAC = "<MAC>"
AUTH_KEY_HEX = "<auth key>"
AUTH_KEY = bytes.fromhex(AUTH_KEY_HEX)

CHAR_CHUNKED_WRITE = "00000016-0000-3512-2118-0009af100700"
CHAR_CHUNKED_READ  = "00000017-0000-3512-2118-0009af100700"

ENDPOINT_AUTH = 0x0082

# Huami protocol constants
RESPONSE = 0x10
SUCCESS = 0x01
CMD_PUB_KEY = 0x04
CMD_SESSION_KEY = 0x05


# --- AES helper -----------------------------------------------------------

def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """AES-128-ECB no padding, matching Gadgetbridge CryptoUtils.encryptAES."""
    assert len(key) == 16
    assert len(data) % 16 == 0
    c = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return c.update(data) + c.finalize()


# --- chunked-2021 encoder (write side) ------------------------------------

class ChunkedEncoder:
    """Host→device chunked framing with extended flags.

    Port of Huami2021ChunkedEncoder.java, minus encryption path (auth runs
    unencrypted). After auth, sharedSessionKey enables encrypt=True.
    """

    HEADER_FIRST = 11  # 0x03 + flags + 0x00 + handle + count + length(4) + type(2)
    HEADER_CONT = 5    # 0x03 + flags + 0x00 + handle + count

    def __init__(self, mtu: int = 247):
        self.mtu = mtu
        self.write_handle = 0

    def max_payload(self, is_first: bool) -> int:
        hdr = self.HEADER_FIRST if is_first else self.HEADER_CONT
        # Gadgetbridge calcMaxWriteChunk = mtu - 3 (ATT header).
        return (self.mtu - 3) - hdr

    def encode(self, endpoint: int, data: bytes, encrypt: bool = False) -> list[bytes]:
        if encrypt:
            raise NotImplementedError("encrypted chunked not needed for auth")

        self.write_handle = (self.write_handle + 1) & 0xFF
        chunks: list[bytes] = []
        remaining = len(data)
        offset = 0
        count = 0
        length = len(data)

        while remaining > 0:
            is_first = count == 0
            hdr = self.HEADER_FIRST if is_first else self.HEADER_CONT
            max_payload = self.max_payload(is_first)
            take = min(remaining, max_payload)
            flags = 0
            if is_first:
                flags |= 0x01
            if remaining <= max_payload:
                flags |= 0x02  # last
                flags |= 0x04  # needs ack

            buf = bytearray(hdr + take)
            buf[0] = 0x03
            buf[1] = flags
            buf[2] = 0x00  # extended flags zero byte
            buf[3] = self.write_handle
            buf[4] = count
            if is_first:
                buf[5] = length & 0xFF
                buf[6] = (length >> 8) & 0xFF
                buf[7] = (length >> 16) & 0xFF
                buf[8] = (length >> 24) & 0xFF
                buf[9] = endpoint & 0xFF
                buf[10] = (endpoint >> 8) & 0xFF
            buf[hdr:] = data[offset:offset + take]
            chunks.append(bytes(buf))
            offset += take
            remaining -= take
            count += 1

        return chunks


# --- chunked-2021 decoder (read side) -------------------------------------

class ChunkedDecoder:
    """Device→host chunked reassembly w/ extended flags. Auth-path only
    handles plaintext; post-auth encrypted payloads would need session key."""

    def __init__(self):
        self.current_handle: Optional[int] = None
        self.current_type: int = 0
        self.current_length: int = 0
        self.buf = bytearray()

    def feed(self, data: bytes) -> Optional[tuple[int, bytes]]:
        if not data or data[0] != 0x03:
            return None
        i = 1
        flags = data[i]; i += 1
        encrypted = bool(flags & 0x08)
        first = bool(flags & 0x01)
        last = bool(flags & 0x02)
        # extended-flags byte (always present for Zepp OS 2021+)
        i += 1
        handle = data[i]; i += 1
        count = data[i]; i += 1

        if self.current_handle is not None and self.current_handle != handle:
            print(f"  [decoder] dropping stray handle {handle}, expected {self.current_handle}")
            return None

        if first:
            full_length = (data[i] | (data[i+1] << 8) | (data[i+2] << 16) | (data[i+3] << 24))
            i += 4
            self.current_length = full_length
            if encrypted:
                enc_len = full_length + 8
                overflow = enc_len % 16
                if overflow:
                    enc_len += 16 - overflow
                full_length = enc_len
            self.buf = bytearray()
            self.current_type = data[i] | (data[i+1] << 8)
            i += 2
            self.current_handle = handle

        self.buf.extend(data[i:])
        if last:
            if encrypted:
                # not expected during auth
                self._reset()
                return None
            payload = bytes(self.buf[:self.current_length])
            t = self.current_type
            self._reset()
            return (t, payload)
        return None

    def _reset(self):
        self.current_handle = None
        self.current_type = 0
        self.current_length = 0
        self.buf = bytearray()


# --- auth orchestration ---------------------------------------------------

async def run_auth():
    priv, pub = huami_ecdh.generate_keypair()
    print(f"generated ECDH keypair")
    print(f"  priv: {priv.hex()}")
    print(f"  pub:  {pub.hex()}")

    decoder = ChunkedDecoder()
    payload_queue: asyncio.Queue[tuple[int, bytes]] = asyncio.Queue()

    def on_read(_sender, data: bytearray):
        print(f"  <- raw {len(data)}B: {bytes(data).hex()}")
        result = decoder.feed(bytes(data))
        if result is not None:
            payload_queue.put_nowait(result)

    async with BleakClient(MAC) as cli:
        print(f"connected: {cli.is_connected}, mtu={cli.mtu_size}")
        encoder = ChunkedEncoder(mtu=max(cli.mtu_size or 23, 23))

        await cli.start_notify(CHAR_CHUNKED_READ, on_read)
        print("subscribed to chunked-read char")

        # Stage 1: send pub key command
        pub_cmd = bytes([CMD_PUB_KEY, 0x02, 0x00, 0x02]) + pub
        print(f"\n[stage 1] sending pub key cmd ({len(pub_cmd)}B)")
        for chunk in encoder.encode(ENDPOINT_AUTH, pub_cmd):
            print(f"  -> {len(chunk)}B: {chunk.hex()}")
            await cli.write_gatt_char(CHAR_CHUNKED_WRITE, chunk, response=False)

        # Wait for response
        try:
            ep_type, payload = await asyncio.wait_for(payload_queue.get(), timeout=10.0)
        except asyncio.TimeoutError:
            print("!! timeout waiting for pub key response")
            return

        print(f"\n[stage 1 reply] type=0x{ep_type:04x} payload={payload.hex()}")
        if ep_type != ENDPOINT_AUTH:
            print(f"!! unexpected endpoint")
            return
        if payload[0] != RESPONSE or payload[1] != CMD_PUB_KEY:
            print(f"!! unexpected header bytes")
            return
        if payload[2] != SUCCESS:
            print(f"!! pub key cmd failed, status=0x{payload[2]:02x}")
            return

        remote_random = payload[3:19]
        remote_pub = payload[19:19+48]
        print(f"  remote_random: {remote_random.hex()}")
        print(f"  remote_pub:    {remote_pub.hex()}")

        # Derive shared secret + session key
        shared_ec = huami_ecdh.generate_shared(priv, remote_pub)
        print(f"  shared_ec:     {shared_ec.hex()}")
        encrypted_seq_nr = struct.unpack("<I", shared_ec[0:4])[0]
        session_key = bytes(shared_ec[i + 8] ^ AUTH_KEY[i] for i in range(16))
        print(f"  session_key:   {session_key.hex()}")
        print(f"  encrypted_seq: {encrypted_seq_nr}")

        enc_rand_1 = aes_ecb_encrypt(AUTH_KEY, remote_random)
        enc_rand_2 = aes_ecb_encrypt(session_key, remote_random)
        session_cmd = bytes([CMD_SESSION_KEY]) + enc_rand_1 + enc_rand_2

        print(f"\n[stage 2] sending session key cmd ({len(session_cmd)}B)")
        for chunk in encoder.encode(ENDPOINT_AUTH, session_cmd):
            print(f"  -> {len(chunk)}B: {chunk.hex()}")
            await cli.write_gatt_char(CHAR_CHUNKED_WRITE, chunk, response=False)

        try:
            ep_type, payload = await asyncio.wait_for(payload_queue.get(), timeout=10.0)
        except asyncio.TimeoutError:
            print("!! timeout waiting for session key response")
            return

        print(f"\n[stage 2 reply] type=0x{ep_type:04x} payload={payload.hex()}")
        if payload[0] != RESPONSE or payload[1] != CMD_SESSION_KEY:
            print("!! unexpected session key reply")
            return
        if payload[2] == 0x25:
            print("!! wrong auth key")
            return
        if payload[2] != SUCCESS:
            print(f"!! session key cmd failed, status=0x{payload[2]:02x}")
            return

        print("\n*** AUTH SUCCESS ***")
        print(f"session_key:    {session_key.hex()}")
        print(f"encrypted_seq:  {encrypted_seq_nr}")
        print("Keep these for follow-up chunked-2021 encrypted traffic.")

        await asyncio.sleep(0.5)
        await cli.stop_notify(CHAR_CHUNKED_READ)


if __name__ == "__main__":
    asyncio.run(run_auth())
