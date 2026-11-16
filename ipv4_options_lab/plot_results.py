#!/usr/bin/env python3
"""Generate publication-friendly PNG and vector PDF from analyzed trial CSVs."""
import argparse
import csv
import json
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run-dir", required=True, type=Path)
    p.add_argument("--out", type=Path, help="Output stem; defaults to run-dir/figures/header_channel")
    args = p.parse_args()
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:
        p.error("Matplotlib is needed: python3 -m pip install matplotlib")
    with (args.run_dir / "trials.csv").open(newline="") as f:
        trials = list(csv.DictReader(f))
    trials = [r for r in trials if r["traffic"] == "covert"]
    if not trials:
        p.error("no covert trials in trials.csv")
    out = args.out or (args.run_dir / "figures" / "header_channel")
    out.parent.mkdir(parents=True, exist_ok=True)
    conditions = sorted({r["condition"] for r in trials})
    fig, axs = plt.subplots(1, 3, figsize=(12, 3.6), constrained_layout=True)
    specs = (("message_success", "Message reconstruction", "Fraction of trials"),
             ("loss_rate", "Packet loss", "Fraction of packets"),
             ("goodput_bps", "Correct bit goodput", "bits/s"))
    for ax, (key, title, ylabel) in zip(axs, specs):
        samples = [[float(r[key]) if key != "message_success" else float(r[key] == "True")
                    for r in trials if r["condition"] == c and r[key] != ""] for c in conditions]
        avg = [sum(s) / len(s) if s else 0 for s in samples]
        ax.bar(conditions, avg, color="#3269a8", width=.65)
        for j, group in enumerate(samples):
            ax.scatter([j] * len(group), group, color="#14263d", s=12, zorder=3)
        ax.set_title(title)
        ax.set_ylabel(ylabel)
        ax.tick_params(axis="x", rotation=25)
        if key != "goodput_bps":
            ax.set_ylim(0, 1.05)
    for ext in ("png", "pdf"):
        fig.savefig(out.with_suffix("." + ext), dpi=250)
    plt.close(fig)
    print(f"Wrote {out.with_suffix('.png')} and {out.with_suffix('.pdf')}")


if __name__ == "__main__":
    main()
