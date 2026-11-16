#!/usr/bin/env python3
"""Transmit an isolated IPv4-options trial and record the actual IP packets."""
import argparse
import json
import struct
import time
import uuid
from pathlib import Path

from scapy.all import IP, ICMP, IPOption_NOP, Raw, PcapWriter, send

MAGIC = b"IPOPTLAB"  # Identifies experiment packets; carries no message bit.
ZERO = bytes.fromhex("01010101")          # Four IPv4 NOP options (IHL=6).
ONE = bytes.fromhex("0101010101010101")  # Eight IPv4 NOP options (IHL=7).


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--trial-id", required=True, type=uuid.UUID)
    p.add_argument("--src", required=True, help="Sender VM's IP address")
    p.add_argument("--dst", required=True, help="Receiver VM's IP address")
    p.add_argument("--message", required=True, help="UTF-8 text; stored locally, never in packet payload")
    p.add_argument("--interval", type=float, default=0.1)
    p.add_argument("--traffic", choices=("covert", "benign-options", "benign-no-options"), default="covert")
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    if not 0.02 <= args.interval <= 10:
        p.error("interval must be between 0.02 and 10 seconds")
    bits = "".join(f"{b:08b}" for b in args.message.encode("utf-8"))
    if not bits or len(bits) > 65535:
        p.error("message must be nonempty and at most 65535 bits (8191 UTF-8 bytes)")
    args.out.mkdir(parents=True, exist_ok=True)
    rows = []
    started = time.monotonic()
    with PcapWriter(str(args.out / "sent.pcap"), sync=True) as capture:
        for seq, bit in enumerate(bits):
            # IP.options is a PacketListField. Passing raw bytes can be reinterpreted
            # during construction; use Scapy option objects and inspect the result.
            options = ([IPOption_NOP() for _ in range(8 if bit == "1" else 4)]
                       if args.traffic == "covert" else
                       [IPOption_NOP()] * 4 if args.traffic == "benign-options" else [])
            expected_options = (ONE if bit == "1" else ZERO) if args.traffic == "covert" else (
                               ZERO if args.traffic == "benign-options" else b"")
            # ICMP payload is *only* public trial bookkeeping, never the secret bit.
            payload = MAGIC + args.trial_id.bytes + struct.pack("!HH", seq, len(bits))
            packet = IP(src=args.src, dst=args.dst, ttl=64, options=options) / ICMP(
                type=8, id=args.trial_id.int & 0xffff, seq=seq
            ) / Raw(payload)
            wire = IP(bytes(packet))  # Fill lengths/checksums before capture and comparison.
            actual_options = bytes(wire)[20:wire.ihl * 4]
            if actual_options != expected_options or bytes(IP(bytes(wire)))[20:wire.ihl * 4] != expected_options:
                raise RuntimeError(f"seq={seq}: Scapy serialized {actual_options.hex()} instead of "
                                   f"{expected_options.hex()}; trial aborted before sending this packet")
            sent_at = time.monotonic()
            send(wire, verbose=False)
            capture.write(wire)
            rows.append({"seq": seq, "expected_bit": int(bit) if args.traffic == "covert" else None,
                         "options_hex": actual_options.hex(),
                         "ttl": wire.ttl, "checksum": wire.chksum, "sent_monotonic": sent_at})
            if seq + 1 < len(bits):
                deadline = started + (seq + 1) * args.interval
                time.sleep(max(0, deadline - time.monotonic()))
    finished = time.monotonic()
    result = {"trial_id": str(args.trial_id), "traffic": args.traffic,
              "message": args.message if args.traffic == "covert" else None,
              "bit_count": len(bits), "interval_seconds": args.interval,
              "sender_duration_seconds": finished - started, "packets": rows}
    (args.out / "sent.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"trial_id": str(args.trial_id), "sent": len(rows)}), flush=True)


if __name__ == "__main__":
    main()
