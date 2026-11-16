#!/usr/bin/env python3
"""Analyze packet logs, annotate security evidence, and export paper-ready CSV/plots."""
import argparse
import csv
import json
from pathlib import Path

FIELDS = ("trial_id", "condition", "traffic", "sent", "received_unique", "lost", "loss_rate",
          "bit_errors", "bit_erasures", "bit_error_rate_observed", "message_success",
          "modified_options", "unexpected_options", "duplicate_packets", "out_of_range_packets",
          "trial_seconds", "goodput_bps", "security_alert", "firewall_drop", "rule_match")


def load_evidence(path):
    if not path.exists():
        return {}
    result = {}
    with path.open(newline="") as f:
        for row in csv.DictReader(f):
            if row.get("trial_id"):
                result[row["trial_id"]] = row
    return result


def answer(value):
    value = (value or "unknown").strip().lower()
    return True if value == "yes" else False if value == "no" else None


def analyze_trial(path, evidence):
    sent = json.loads((path / "sent.json").read_text())
    received = json.loads((path / "received.json").read_text())
    meta = json.loads((path / "manifest.json").read_text())
    trial_id = sent["trial_id"]
    if received["trial_id"] != trial_id or meta["trial_id"] != trial_id:
        raise ValueError(f"Trial ID mismatch in {path}")
    originals = {int(p["seq"]): p for p in sent["packets"]}
    observed = {}
    duplicates = out_of_range = 0
    for packet in received["packets"]:
        seq = int(packet["seq"])
        if seq not in originals or packet["total"] != len(originals):
            out_of_range += 1
        elif seq in observed:
            duplicates += 1
        else:
            observed[seq] = packet
    matched = set(originals) & set(observed)
    covert = sent["traffic"] == "covert"
    errors = sum(observed[i]["decoded_bit"] is not None and
                 observed[i]["decoded_bit"] != originals[i]["expected_bit"]
                 for i in matched) if covert else 0
    undecodable = sum(observed[i]["decoded_bit"] is None for i in matched) if covert else 0
    decoded = len(matched) - undecodable if covert else 0
    modified = sum(observed[i]["options_hex"] != originals[i]["options_hex"] for i in matched)
    unexpected = (sum(observed[i]["decoded_bit"] is None for i in matched) if covert else
                  sum(observed[i]["options_hex"] != originals[i]["options_hex"] for i in matched))
    duration = max(float(sent["sender_duration_seconds"]) + float(meta["grace_seconds"]), 0.001)
    e = evidence.get(trial_id, {})
    row = {"trial_id": trial_id, "condition": meta["condition"], "traffic": sent["traffic"],
           "sent": len(originals), "received_unique": len(matched),
           "lost": len(originals) - len(matched),
           "loss_rate": (len(originals) - len(matched)) / len(originals),
           "bit_errors": errors if covert else None, "bit_erasures": len(originals) - decoded if covert else None,
           "bit_error_rate_observed": errors / decoded if covert and decoded else None,
           "message_success": (decoded == len(originals) and errors == 0) if covert else None,
           "modified_options": modified, "unexpected_options": unexpected,
           "duplicate_packets": duplicates, "out_of_range_packets": out_of_range,
           "trial_seconds": duration, "goodput_bps": (decoded - errors) / duration if covert else None,
           "security_alert": answer(e.get("security_alert")),
           "firewall_drop": answer(e.get("firewall_drop")),
           "rule_match": answer(e.get("rule_match"))}
    detail = {"trial_id": trial_id, "condition": meta["condition"], "traffic": sent["traffic"],
              "decoded_bitstring": "".join(str(observed[i]["decoded_bit"]) if i in observed and
                                           observed[i]["decoded_bit"] is not None else "?"
                                           for i in sorted(originals)) if covert else None,
              "received_text": None, "unmatched_sequences": sorted(set(originals) - matched),
              "modified_sequences": [i for i in sorted(matched) if observed[i]["options_hex"] != originals[i]["options_hex"]],
              "evidence": e, "metrics": row}
    if covert and row["message_success"]:
        detail["received_text"] = bytes(int(detail["decoded_bitstring"][i:i+8], 2)
                                         for i in range(0, len(originals), 8)).decode("utf-8", errors="replace")
    return row, detail


def summarize(rows):
    groups = {}
    for row in rows:
        groups.setdefault((row["condition"], row["traffic"]), []).append(row)
    result = []
    for (condition, traffic), group in sorted(groups.items()):
        known = [x for x in group if x["security_alert"] is not None]
        covert = traffic == "covert"
        nbits = sum(x["sent"] for x in group)
        observed_bits = sum(x["sent"] - x["bit_erasures"] for x in group) if covert else 0
        result.append({"condition": condition, "traffic": traffic, "trials": len(group),
                       "message_success_rate": sum(x["message_success"] for x in group) / len(group) if covert else None,
                       "loss_rate": sum(x["lost"] for x in group) / nbits,
                       "bit_erasure_rate": sum(x["bit_erasures"] for x in group) / nbits if covert else None,
                       "bit_error_rate_observed": sum(x["bit_errors"] for x in group) / observed_bits if observed_bits else None,
                       "mean_goodput_bps": sum(x["goodput_bps"] for x in group) / len(group) if covert else None,
                       "modified_options": sum(x["modified_options"] for x in group),
                       "security_alert_rate": sum(x["security_alert"] for x in known) / len(known) if known else None,
                       "detection_rate": (sum(x["security_alert"] for x in known) / len(known)
                                          if known and covert else None),
                       "false_positive_rate": (sum(x["security_alert"] for x in known) / len(known)
                                               if known and not covert else None),
                       "security_alert_evaluated": len(known), "security_alert_unknown": len(group) - len(known)})
    return result


def write_csv(path, rows, fields):
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def plot_summary(summary, dest):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    rows = [x for x in summary if x["traffic"] == "covert"]
    if not rows:
        return
    fig, axes = plt.subplots(1, 3, figsize=(12, 3.6), constrained_layout=True)
    labels = [x["condition"] for x in rows]
    for ax, key, title in zip(axes, ("message_success_rate", "loss_rate", "mean_goodput_bps"),
                              ("Message success", "Packet loss", "Goodput")):
        ax.bar(labels, [x[key] or 0 for x in rows], color="#3269a8")
        ax.set_title(title)
        ax.tick_params(axis="x", rotation=25)
        ax.set_ylabel("bits/s" if key == "mean_goodput_bps" else "fraction")
        if key != "mean_goodput_bps":
            ax.set_ylim(0, 1)
    fig.savefig(dest, dpi=200)
    fig.savefig(dest.with_suffix(".pdf"))
    plt.close(fig)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run-dir", type=Path, required=True)
    p.add_argument("--plot", action="store_true", help="Create comparison.png and comparison.pdf (requires matplotlib)")
    args = p.parse_args()
    directory = args.run_dir
    evidence = load_evidence(directory / "evidence.csv")
    rows = []
    for manifest in sorted(directory.glob("trials/*/manifest.json")):
        try:
            row, detail = analyze_trial(manifest.parent, evidence)
        except FileNotFoundError:
            print(f"SKIPPED incomplete trial: {manifest.parent}")
            continue
        rows.append(row)
        (manifest.parent / "results.json").write_text(json.dumps(detail, indent=2) + "\n")
    if not rows:
        p.error("no complete trials found")
    write_csv(directory / "trials.csv", rows, FIELDS)
    summary = summarize(rows)
    write_csv(directory / "summary.csv", summary, tuple(summary[0]))
    (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    if args.plot:
        plot_summary(summary, directory / "comparison.png")
    print(f"Analyzed {len(rows)} trials; wrote trials.csv, summary.csv, summary.json")
    print("Security alert rates remain unknown where evidence.csv says unknown.")


if __name__ == "__main__":
    main()
