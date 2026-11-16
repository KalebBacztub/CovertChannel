#!/usr/bin/env python3
"""Capture one identified experiment's ICMP echoes on the receiver VM."""
import argparse
import json
import struct
import time
import uuid
from pathlib import Path

from scapy.all import IP, ICMP, Raw, PcapWriter, conf, sniff

MAGIC = b"IPOPTLAB"
ZERO = bytes.fromhex("01010101")
ONE = bytes.fromhex("0101010101010101")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--trial-id", required=True, type=uuid.UUID)
    p.add_argument("--iface", required=True, help="Receiver interface on the intended route")
    p.add_argument("--src", required=True)
    p.add_argument("--dst", required=True)
    p.add_argument("--duration", required=True, type=float)
    p.add_argument("--expected-packets", type=int,
                   help="Finish early once all unique packet positions arrive; still time out if some are lost")
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()
    if not 1 <= args.duration <= 3600:
        p.error("duration must be between 1 and 3600 seconds")
    if args.expected_packets is not None and not 1 <= args.expected_packets <= 65535:
        p.error("expected-packets must be between 1 and 65535")
    args.out.mkdir(parents=True, exist_ok=True)
    rows = []
    with PcapWriter(str(args.out / "received.pcap"), sync=True) as capture:
        def handle(packet):
            if IP not in packet or ICMP not in packet or Raw not in packet:
                return
            ip, icmp = packet[IP], packet[ICMP]
            if ip.src != args.src or ip.dst != args.dst or icmp.type != 8:
                return
            payload = bytes(icmp.payload)
            if len(payload) != 28 or payload[:8] != MAGIC or payload[8:24] != args.trial_id.bytes:
                return
            seq, total = struct.unpack("!HH", payload[24:28])
            options = bytes(ip)[20:ip.ihl * 4]
            bit = 0 if options == ZERO else 1 if options == ONE else None
            rows.append({"seq": seq, "total": total, "decoded_bit": bit,
                         "options_hex": options.hex(), "ttl": ip.ttl,
                         "checksum": ip.chksum, "arrival_monotonic": time.monotonic()})
            capture.write(packet)

        # Opening the socket before READY removes the race with the sender.
        socket = conf.L2listen(iface=args.iface)
        started = time.monotonic()
        print("READY", flush=True)
        try:
            sniff(opened_socket=socket, prn=handle, store=False, timeout=args.duration,
                  stop_filter=(lambda _: len({r["seq"] for r in rows}) >= args.expected_packets)
                  if args.expected_packets is not None else None)
        finally:
            socket.close()
    result = {"trial_id": str(args.trial_id), "iface": args.iface,
              "capture_duration_seconds": time.monotonic() - started, "packets": rows}
    (args.out / "received.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"trial_id": str(args.trial_id), "received": len(rows)}), flush=True)


if __name__ == "__main__":
    main()
