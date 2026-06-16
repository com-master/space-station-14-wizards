#!/usr/bin/env python3
"""
Lidgren/RobustToolbox UDP packet sniffer for Space Station 14.

Parses the two-layer format:
  Layer 1 – Lidgren: [type:1][seq+frag:2][len_bits:2][payload:N] (5-byte header per chunk)
  Layer 2 – RobustToolbox: [msg_id:1][data...]  (after optional AES decryption)

Usage:
  sudo python3 lidgren_udp_sniffer.py [--port 1212] [--iface lo] [--no-color]

Notes:
  - Requires raw socket access (run as root or with CAP_NET_RAW).
  - Post-handshake packets ARE encrypted by default (net.encrypt = true).
    To see decrypted payloads, start the server with `net.encrypt false`
    or pass a captured session key via --aes-key.
  - StringTable (msg_id 0) is always sent unencrypted during handshake,
    so the tool learns msg names automatically regardless of encryption.
"""

import argparse
import socket
import struct
import sys
import textwrap
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# Lidgren NetMessageType values (NetMessageType.cs)
# ---------------------------------------------------------------------------
NET_MSG_TYPES = {
    0:   "Unconnected",
    1:   "UserUnreliable",
    **{i: f"UserSequenced{i-1}"          for i in range(2, 34)},
    34:  "UserReliableUnordered",
    **{i: f"UserReliableSequenced{i-34}" for i in range(35, 67)},
    **{i: f"UserReliableOrdered{i-66}"   for i in range(67, 99)},
    129: "Ping",
    130: "Pong",
    131: "Connect",
    132: "ConnectResponse",
    133: "ConnectionEstablished",
    134: "Acknowledge",
    135: "Disconnect",
    136: "Discovery",
    137: "DiscoveryResponse",
    138: "NatPunchMessage",
    139: "NatIntroduction",
    140: "ExpandMTURequest",
    141: "ExpandMTUSuccess",
    142: "NatIntroductionConfirmRequest",
    143: "NatIntroductionConfirmed",
}

USER_DATA_TYPES = set(range(1, 99))  # types that carry application payload

# ANSI colours
C_RESET  = "\033[0m"
C_GRAY   = "\033[90m"
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN   = "\033[96m"
C_RED    = "\033[91m"
C_BOLD   = "\033[1m"

USE_COLOR = True


def col(c: str, s: str) -> str:
    return (c + s + C_RESET) if USE_COLOR else s


# ---------------------------------------------------------------------------
# Variable-length integer decoder (Lidgren zigzag LEB128)
# ---------------------------------------------------------------------------
def read_varuint32(data: bytes, offset: int) -> tuple[int, int]:
    """Returns (value, new_offset). Lidgren VarUInt: 7 bits per byte, MSB=more."""
    result = 0
    shift = 0
    while offset < len(data):
        b = data[offset]
        offset += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    return result, offset


def read_varint32(data: bytes, offset: int) -> tuple[int, int]:
    """Zigzag-decoded signed VarInt32."""
    n, offset = read_varuint32(data, offset)
    return (n >> 1) ^ -(n & 1), offset


def read_string(data: bytes, offset: int) -> tuple[str, int]:
    """Lidgren string: VarUInt32 byte_length + UTF-8 bytes."""
    byte_len, offset = read_varuint32(data, offset)
    s = data[offset: offset + byte_len].decode("utf-8", errors="replace")
    return s, offset + byte_len


def read_uint32_le(data: bytes, offset: int) -> tuple[int, int]:
    val = struct.unpack_from("<I", data, offset)[0]
    return val, offset + 4


# ---------------------------------------------------------------------------
# StringTable state (per connection pair)
# ---------------------------------------------------------------------------
@dataclass
class ConnectionState:
    src: str
    dst: str
    string_table: dict = field(default_factory=lambda: {0: "MsgStringTableEntries"})
    pkt_count: int = 0

    def name_for_id(self, msg_id: int) -> str:
        return self.string_table.get(msg_id, f"<unknown#{msg_id}>")


# ---------------------------------------------------------------------------
# Lidgren header parser
# ---------------------------------------------------------------------------
LIDGREN_HEADER = 5  # bytes


@dataclass
class LidgrenChunk:
    msg_type: int
    seq_num: int
    is_fragment: bool
    payload_bits: int
    payload: bytes


def parse_lidgren_chunks(udp_payload: bytes) -> list[LidgrenChunk]:
    """
    A single UDP datagram may contain multiple Lidgren chunks back-to-back.
    Each chunk: [type:u8][seq_lo+frag:u8][seq_hi:u8][len_bits:u16le][payload...]
    """
    chunks = []
    offset = 0
    while offset + LIDGREN_HEADER <= len(udp_payload):
        msg_type = udp_payload[offset]
        b1 = udp_payload[offset + 1]
        b2 = udp_payload[offset + 2]
        seq_num = ((b2 & 0x7F) << 8) | b1  # lower 15 bits
        is_fragment = bool(b2 & 0x80)
        payload_bits = struct.unpack_from("<H", udp_payload, offset + 3)[0]
        payload_bytes = (payload_bits + 7) >> 3
        offset += LIDGREN_HEADER

        if offset + payload_bytes > len(udp_payload):
            # truncated – take what's available
            payload = udp_payload[offset:]
            offset = len(udp_payload)
        else:
            payload = udp_payload[offset: offset + payload_bytes]
            offset += payload_bytes

        chunks.append(LidgrenChunk(msg_type, seq_num, is_fragment, payload_bits, payload))

    return chunks


# ---------------------------------------------------------------------------
# RobustToolbox payload parser
# ---------------------------------------------------------------------------
def try_parse_string_table(payload: bytes) -> Optional[list[tuple[int, str]]]:
    """
    MsgStringTableEntries payload (ID already consumed):
      UInt32 count + for each entry: VarInt32 id + String name
    """
    if len(payload) < 4:
        return None
    try:
        count, off = read_uint32_le(payload, 0)
        if count > 10_000:
            return None
        entries = []
        for _ in range(count):
            eid, off = read_varint32(payload, off)
            name, off = read_string(payload, off)
            entries.append((eid, name))
        return entries
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Hex dump helper
# ---------------------------------------------------------------------------
def hexdump(data: bytes, indent: int = 4, width: int = 16) -> str:
    lines = []
    pad = " " * indent
    for i in range(0, len(data), width):
        chunk = data[i: i + width]
        hex_part  = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{pad}{i:04x}  {hex_part:<{width*3}}  {ascii_part}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Packet handler
# ---------------------------------------------------------------------------
def handle_packet(
    raw: bytes,
    src_addr: tuple,
    dst_addr: tuple,
    conn_states: dict,
    server_port: int,
    aes_key: Optional[bytes],
    verbose: bool,
) -> None:

    if len(raw) < LIDGREN_HEADER:
        return

    src_key = f"{src_addr[0]}:{src_addr[1]}"
    dst_key = f"{dst_addr[0]}:{dst_addr[1]}"
    pair_key = tuple(sorted([src_key, dst_key]))

    if pair_key not in conn_states:
        conn_states[pair_key] = ConnectionState(src=src_key, dst=dst_key)
    state = conn_states[pair_key]
    state.pkt_count += 1

    is_to_server = dst_addr[1] == server_port
    direction = col(C_GREEN, "C→S") if is_to_server else col(C_CYAN, "S→C")

    chunks = parse_lidgren_chunks(raw)
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    for chunk in chunks:
        mt_name = NET_MSG_TYPES.get(chunk.msg_type, f"type={chunk.msg_type}")
        is_user = chunk.msg_type in USER_DATA_TYPES

        header = (
            f"{col(C_GRAY, ts)} {direction} "
            f"{col(C_BOLD, mt_name)} "
            f"seq={chunk.seq_num} "
            f"{'[FRAG] ' if chunk.is_fragment else ''}"
            f"payload={len(chunk.payload)}B"
        )

        if not is_user or len(chunk.payload) == 0:
            print(header)
            continue

        # RobustToolbox: first byte is msg_id from StringTable
        msg_id = chunk.payload[0]
        rt_payload = chunk.payload[1:]
        msg_name = state.name_for_id(msg_id)

        # Try AES decrypt if key provided (after handshake)
        decrypted = False
        if aes_key and msg_name == f"<unknown#{msg_id}>":
            try:
                from Crypto.Cipher import AES
                # RobustToolbox uses AES-128-GCM; nonce is prepended (12 bytes)
                if len(rt_payload) >= 28:  # 12 nonce + 16 tag minimum
                    nonce = rt_payload[:12]
                    ciphertext = rt_payload[12:]
                    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                    rt_payload = cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
                    decrypted = True
            except Exception:
                pass

        if msg_name == "MsgStringTableEntries" and not decrypted:
            entries = try_parse_string_table(rt_payload)
            if entries:
                for eid, ename in entries:
                    state.string_table[eid] = ename
                entry_list = ", ".join(f"{eid}={ename}" for eid, ename in entries[:8])
                if len(entries) > 8:
                    entry_list += f"… (+{len(entries)-8} more)"
                print(
                    f"{header} "
                    f"| {col(C_YELLOW, msg_name)} "
                    f"({col(C_YELLOW, f'{len(entries)} entries')}: {entry_list})"
                )
                continue

        enc_note = ""
        if aes_key is None and msg_name.startswith("<unknown"):
            enc_note = col(C_RED, " [possibly encrypted]")
        elif decrypted:
            enc_note = col(C_GREEN, " [decrypted]")

        print(
            f"{header} "
            f"| {col(C_YELLOW, msg_name)}{enc_note} "
            f"rt_payload={len(rt_payload)}B"
        )

        if verbose:
            print(hexdump(chunk.payload))


# ---------------------------------------------------------------------------
# Raw UDP capture using raw sockets
# ---------------------------------------------------------------------------
def capture_raw(iface: str, port: int, args) -> None:
    """
    Capture UDP packets on all interfaces using a raw socket.
    On Linux this requires root or CAP_NET_RAW.
    """
    # ETH_P_IP = 0x0800
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    if iface:
        s.bind((iface, 0))

    conn_states: dict = {}
    aes_key: Optional[bytes] = None
    if args.aes_key:
        raw_key = bytes.fromhex(args.aes_key)
        aes_key = raw_key[:16]  # AES-128

    print(col(C_BOLD, f"[lidgren_sniffer] listening on {iface or 'all'}, server port {port}"))
    print(col(C_GRAY, "  Ctrl+C to stop. Post-handshake packets are encrypted by default."))
    print(col(C_GRAY, "  Launch server with `net.encrypt false` to see plaintext payloads."))
    print()

    try:
        while True:
            raw_pkt, _ = s.recvfrom(65535)

            # Ethernet header: 14 bytes
            if len(raw_pkt) < 14:
                continue
            eth_type = struct.unpack_from("!H", raw_pkt, 12)[0]
            if eth_type != 0x0800:
                continue  # not IPv4

            # IP header: IHL field (lower nibble of byte 14) * 4 bytes
            ip_start = 14
            if len(raw_pkt) < ip_start + 20:
                continue
            ihl = (raw_pkt[ip_start] & 0x0F) * 4
            protocol = raw_pkt[ip_start + 9]
            if protocol != 17:  # not UDP
                continue

            src_ip = socket.inet_ntoa(raw_pkt[ip_start + 12: ip_start + 16])
            dst_ip = socket.inet_ntoa(raw_pkt[ip_start + 16: ip_start + 20])

            # UDP header: 8 bytes
            udp_start = ip_start + ihl
            if len(raw_pkt) < udp_start + 8:
                continue
            src_port = struct.unpack_from("!H", raw_pkt, udp_start)[0]
            dst_port = struct.unpack_from("!H", raw_pkt, udp_start + 2)[0]

            if src_port != port and dst_port != port:
                continue  # not our SS14 traffic

            udp_payload = raw_pkt[udp_start + 8:]
            if not udp_payload:
                continue

            handle_packet(
                udp_payload,
                (src_ip, src_port),
                (dst_ip, dst_port),
                conn_states,
                server_port=port,
                aes_key=aes_key,
                verbose=args.verbose,
            )

    except KeyboardInterrupt:
        total = sum(s.pkt_count for s in conn_states.values())
        print(f"\n[done] captured {total} packets across {len(conn_states)} connections")


# ---------------------------------------------------------------------------
# Pcap replay mode – parse a .pcap file instead of live capture
# ---------------------------------------------------------------------------
def replay_pcap(path: str, port: int, args) -> None:
    """
    Minimal pcap parser (no scapy needed).
    Supports pcap (little-endian) with linktype LINKTYPE_ETHERNET (1).
    """
    with open(path, "rb") as f:
        magic = struct.unpack("<I", f.read(4))[0]
        if magic not in (0xA1B2C3D4, 0xA1B23C4D):
            sys.exit("Not a pcap file (check magic bytes)")
        _ver_maj, _ver_min, _thiszone, _sigfigs, snaplen, linktype = struct.unpack("<HHiIII", f.read(20))
        if linktype not in (1, 101):  # Ethernet or raw IP
            sys.exit(f"Unsupported linktype {linktype}; only Ethernet(1) and RawIP(101) supported")

        conn_states: dict = {}
        aes_key: Optional[bytes] = None
        if args.aes_key:
            raw_key = bytes.fromhex(args.aes_key)
            aes_key = raw_key[:16]

        print(col(C_BOLD, f"[lidgren_sniffer] replaying {path}, server port {port}"))
        count = 0

        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", hdr)
            frame = f.read(incl_len)
            if len(frame) < incl_len:
                break

            if linktype == 1:
                # Ethernet
                if len(frame) < 14:
                    continue
                eth_type = struct.unpack_from("!H", frame, 12)[0]
                if eth_type != 0x0800:
                    continue
                ip_start = 14
            else:
                ip_start = 0  # raw IP

            if len(frame) < ip_start + 20:
                continue
            ihl = (frame[ip_start] & 0x0F) * 4
            if frame[ip_start + 9] != 17:
                continue  # not UDP

            src_ip = socket.inet_ntoa(frame[ip_start + 12: ip_start + 16])
            dst_ip = socket.inet_ntoa(frame[ip_start + 16: ip_start + 20])

            udp_start = ip_start + ihl
            if len(frame) < udp_start + 8:
                continue

            src_port = struct.unpack_from("!H", frame, udp_start)[0]
            dst_port = struct.unpack_from("!H", frame, udp_start + 2)[0]

            if src_port != port and dst_port != port:
                continue

            udp_payload = frame[udp_start + 8:]
            if not udp_payload:
                continue

            handle_packet(
                udp_payload,
                (src_ip, src_port),
                (dst_ip, dst_port),
                conn_states,
                server_port=port,
                aes_key=aes_key,
                verbose=args.verbose,
            )
            count += 1

        total = sum(s.pkt_count for s in conn_states.values())
        print(f"\n[done] {count} UDP frames replayed, {total} lidgren packets parsed")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    global USE_COLOR
    parser = argparse.ArgumentParser(
        description="Lidgren/RobustToolbox UDP sniffer for Space Station 14",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Live capture (needs root / CAP_NET_RAW):
              sudo python3 lidgren_udp_sniffer.py --port 1212 --iface lo

              # Replay a pcap captured with tcpdump:
              tcpdump -i lo -w ss14.pcap udp port 1212
              python3 lidgren_udp_sniffer.py --pcap ss14.pcap --port 1212

              # Show hex dumps of every payload:
              sudo python3 lidgren_udp_sniffer.py --port 1212 --verbose

              # Decrypt post-handshake traffic (AES-128 key as hex, 32 chars):
              sudo python3 lidgren_udp_sniffer.py --port 1212 --aes-key AABBCC...
        """),
    )
    parser.add_argument("--port",    type=int, default=1212, help="SS14 server UDP port (default 1212)")
    parser.add_argument("--iface",   default="",            help="Network interface for live capture")
    parser.add_argument("--pcap",    default="",            help="Replay a .pcap file instead of live capture")
    parser.add_argument("--aes-key", default="",            help="AES-128 session key (hex) for decrypting post-handshake packets")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print hex dump of each payload")
    parser.add_argument("--no-color", action="store_true",  help="Disable ANSI colour output")
    args = parser.parse_args()

    if args.no_color:
        USE_COLOR = False

    if args.pcap:
        replay_pcap(args.pcap, args.port, args)
    else:
        if sys.platform != "linux":
            sys.exit("Live capture uses AF_PACKET; Linux only. Use --pcap for other platforms.")
        capture_raw(args.iface, args.port, args)


if __name__ == "__main__":
    main()
