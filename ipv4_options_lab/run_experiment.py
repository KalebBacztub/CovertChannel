#!/usr/bin/env python3
"""Run repeated, paired covert and synthetic-benign trials over two SSH-accessible VMs."""
import argparse
import csv
import hashlib
import json
import re
import shlex
import subprocess
import sys
import time
import uuid
from pathlib import Path

EVIDENCE_FIELDS = ("trial_id", "security_alert", "firewall_drop", "rule_match", "evidence_reference")


def call(argv, **kwargs):
    return subprocess.run(argv, check=True, text=True, **kwargs)


def ssh(target, argv):
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", target, shlex.join(argv)]


def prepare(target, remote_dir, script):
    call(ssh(target, ["mkdir", "-p", remote_dir]))
    call(["scp", "-q", str(Path(__file__).with_name(script)), f"{target}:{remote_dir}/{script}"])


def remote_copy(target, remote_path, local_path):
    call(["scp", "-q", f"{target}:{remote_path}", str(local_path)])


def append_evidence(path, trial_id):
    create = not path.exists()
    with path.open("a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=EVIDENCE_FIELDS)
        if create:
            writer.writeheader()
        writer.writerow({"trial_id": trial_id, "security_alert": "unknown", "firewall_drop": "unknown",
                         "rule_match": "unknown", "evidence_reference": ""})


def check_comparability(directory, args, config_hash):
    common = {"sender_ip": args.sender_ip, "receiver_ip": args.receiver_ip,
              "receiver_iface": args.receiver_iface,
              "message_utf8_sha256": hashlib.sha256(args.message.encode()).hexdigest(),
              "interval_seconds": args.interval, "grace_seconds": args.grace}
    for file in (directory / "trials").glob("*/manifest.json"):
        prior = json.loads(file.read_text())
        differences = [k for k, v in common.items() if prior.get(k) != v]
        if prior.get("condition") == args.condition:
            differences += [k for k, v in {"defense_note": args.defense_note,
                                            "config_sha256": config_hash}.items() if prior.get(k) != v]
        if differences:
            raise ValueError(f"Existing trial {prior.get('trial_id')} is not comparable ({', '.join(differences)}); "
                             "choose a new --run-dir or restore the original parameters")


def collect_manual(args, config_hash):
    """Collect a trial started in two interactive VM shells (SSH can prompt)."""
    trial_id = str(args.collect_trial)
    local = args.run_dir / "trials" / trial_id
    local.mkdir(parents=True, exist_ok=True)
    rx_out = f"{args.remote_dir}/data/{trial_id}/rx"
    tx_out = f"{args.remote_dir}/data/{trial_id}/tx"
    for target, remote, name in ((args.sender, tx_out, "sent"),
                                 (args.receiver, rx_out, "received")):
        for ext in ("json", "pcap"):
            remote_copy(target, f"{remote}/{name}.{ext}", local / f"{name}.{ext}")
    sent = json.loads((local / "sent.json").read_text())
    received = json.loads((local / "received.json").read_text())
    if sent["trial_id"] != trial_id or received["trial_id"] != trial_id:
        raise ValueError("Downloaded sender/receiver trial IDs do not match; no report generated")
    if sent["traffic"] != "covert" or sent["message"] != args.message:
        raise ValueError("Downloaded message/traffic differs from --message; no report generated")
    if sent["interval_seconds"] != args.interval or received["iface"] != args.receiver_iface:
        raise ValueError("Downloaded interval/interface differs from controller arguments")
    manifest = {"trial_id": trial_id, "condition": args.condition, "traffic": "covert",
                "sender": args.sender, "receiver": args.receiver, "sender_ip": args.sender_ip,
                "receiver_ip": args.receiver_ip, "receiver_iface": args.receiver_iface,
                "message_utf8_sha256": hashlib.sha256(args.message.encode()).hexdigest(),
                "interval_seconds": args.interval, "grace_seconds": args.grace,
                "defense_note": args.defense_note, "config_sha256": config_hash,
                "collection_mode": "interactive-manual"}
    (local / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    evidence_file = args.run_dir / "evidence.csv"
    existing = load_evidence_ids(evidence_file)
    if trial_id not in existing:
        append_evidence(evidence_file, trial_id)
    call([sys.executable, str(Path(__file__).with_name("analyze.py")),
          "--run-dir", str(args.run_dir)])
    print(f"Trial results: {local / 'results.json'}")
    print(f"CSV results: {args.run_dir / 'trials.csv'}")


def load_evidence_ids(path):
    if not path.exists():
        return set()
    with path.open(newline="") as f:
        return {row["trial_id"] for row in csv.DictReader(f) if row.get("trial_id")}


def one_trial(args, directory, traffic, config_hash):
    trial_id = str(uuid.uuid4())
    local = directory / "trials" / trial_id
    local.mkdir(parents=True)
    count = len(args.message.encode("utf-8")) * 8
    # The receiver is armed first; its fixed window includes SSH start-up time.
    duration = count * args.interval + args.grace + 8
    if duration > 3600:
        raise ValueError("trial too long for receiver's one-hour maximum")
    rx_out = f"{args.remote_dir}/data/{trial_id}/rx"
    tx_out = f"{args.remote_dir}/data/{trial_id}/tx"
    call(ssh(args.receiver, ["mkdir", "-p", rx_out]))
    call(ssh(args.sender, ["mkdir", "-p", tx_out]))
    manifest = {"trial_id": trial_id, "condition": args.condition, "traffic": traffic,
                "sender": args.sender, "receiver": args.receiver, "sender_ip": args.sender_ip,
                "receiver_ip": args.receiver_ip, "receiver_iface": args.receiver_iface,
                "message_utf8_sha256": hashlib.sha256(args.message.encode()).hexdigest(),
                "interval_seconds": args.interval, "grace_seconds": args.grace,
                "defense_note": args.defense_note, "config_sha256": config_hash,
                "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    (local / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    prefix = ["sudo", "-n"] if args.elevation == "sudo" else []
    receiver_cmd = [*prefix, args.remote_python, f"{args.remote_dir}/receiver.py",
                    "--trial-id", trial_id, "--iface", args.receiver_iface,
                    "--src", args.sender_ip, "--dst", args.receiver_ip,
                    "--duration", str(duration), "--expected-packets", str(count), "--out", rx_out]
    with (local / "receiver.stderr").open("w") as err:
        receiver = subprocess.Popen(ssh(args.receiver, receiver_cmd), stdout=subprocess.PIPE,
                                    stderr=err, text=True, bufsize=1)
        try:
            # readline can wait if remote startup fails silently; poll through communicate
            # is not appropriate because READY must arrive before sending.
            import selectors
            selector = selectors.DefaultSelector()
            selector.register(receiver.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=20):
                raise RuntimeError("receiver did not become READY within 20 seconds")
            if receiver.stdout.readline().strip() != "READY":
                raise RuntimeError("receiver failed to open capture socket; see receiver.stderr")
            sender_cmd = [*prefix, args.remote_python, f"{args.remote_dir}/sender.py",
                          "--trial-id", trial_id, "--src", args.sender_ip, "--dst", args.receiver_ip,
                          "--message", args.message, "--interval", str(args.interval),
                          "--traffic", traffic, "--out", tx_out]
            with (local / "sender.stderr").open("w") as tx_err:
                call(ssh(args.sender, sender_cmd), stdout=tx_err, stderr=subprocess.STDOUT)
            receiver.communicate(timeout=duration + 15)
            if receiver.returncode:
                raise RuntimeError("receiver failed; see receiver.stderr")
            for target, remote, name in ((args.sender, tx_out, "sent"),
                                         (args.receiver, rx_out, "received")):
                files = [f"{remote}/{name}.json", f"{remote}/{name}.pcap"]
                if prefix:
                    call(ssh(target, [*prefix, "chmod", "a+r", *files]))
                for ext in ("json", "pcap"):
                    remote_copy(target, f"{remote}/{name}.{ext}", local / f"{name}.{ext}")
            append_evidence(directory / "evidence.csv", trial_id)
            print(f"{args.condition}: {traffic} trial {trial_id} complete", flush=True)
        finally:
            if receiver.poll() is None:
                receiver.terminate()
                try:
                    receiver.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    receiver.kill()
                    receiver.wait()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sender", required=True, help="SSH destination user@sender_vm")
    p.add_argument("--receiver", required=True, help="SSH destination user@receiver_vm")
    p.add_argument("--sender-ip", required=True)
    p.add_argument("--receiver-ip", required=True)
    p.add_argument("--receiver-iface", required=True)
    p.add_argument("--remote-dir", default="/tmp/ipv4-options-lab")
    p.add_argument("--remote-python", default="/usr/bin/python3")
    p.add_argument("--elevation", choices=("sudo", "none"), default="sudo",
                   help="sudo -n on both VMs (default), or none when the SSH user can capture/send")
    p.add_argument("--condition", required=True, help="e.g. baseline or sophos_rule_1")
    p.add_argument("--defense-note", required=True, help="Exact defense setting, rule ID, or 'none'")
    p.add_argument("--config-file", type=Path, help="Optional exported Sophos rule/config evidence")
    p.add_argument("--message", default="Header test")
    p.add_argument("--interval", type=float, default=0.1)
    p.add_argument("--grace", type=float, default=3.0)
    p.add_argument("--trials", type=int, default=3, help="Covert trials per condition")
    p.add_argument("--controls", type=int, default=1, help="Pairs of benign option/no-option trials")
    p.add_argument("--run-dir", type=Path, default=Path("experiments/ipv4-options"))
    p.add_argument("--collect-trial", type=uuid.UUID,
                   help="Fetch and analyze an interactively run trial; SSH/SCP may prompt")
    args = p.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", args.condition):
        p.error("condition must be 1-48 letters, digits, underscores, or hyphens")
    if not args.remote_dir.startswith("/") or not 0.02 <= args.interval <= 10 or not 1 <= args.grace <= 60:
        p.error("remote-dir must be absolute; interval 0.02-10; grace 1-60")
    if args.trials < 1 or args.controls < 1 or not args.message or len(args.message.encode()) * 8 > 65535:
        p.error("need trials and controls >= 1; message must be 1-8191 UTF-8 bytes")
    args.run_dir.mkdir(parents=True, exist_ok=True)
    config_hash = None
    if args.config_file:
        content = args.config_file.read_bytes()
        config_hash = hashlib.sha256(content).hexdigest()
    check_comparability(args.run_dir, args, config_hash)
    if args.config_file:
        folder = args.run_dir / "configs"
        folder.mkdir(exist_ok=True)
        (folder / f"{args.condition}_{config_hash[:12]}{args.config_file.suffix}").write_bytes(content)
    if args.collect_trial:
        collect_manual(args, config_hash)
        return
    prepare(args.sender, args.remote_dir, "sender.py")
    prepare(args.receiver, args.remote_dir, "receiver.py")
    for i in range(max(args.trials, args.controls)):
        if i < args.trials:
            one_trial(args, args.run_dir, "covert", config_hash)
        if i < args.controls:
            one_trial(args, args.run_dir, "benign-options", config_hash)
            one_trial(args, args.run_dir, "benign-no-options", config_hash)
    call([sys.executable, str(Path(__file__).with_name("analyze.py")),
          "--run-dir", str(args.run_dir)])


if __name__ == "__main__":
    main()
