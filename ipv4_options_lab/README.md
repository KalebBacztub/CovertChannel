# IPv4 options channel experiment

An isolated-lab experiment for the CIT independent study. Every covert bit is one ICMP echo packet. A **0** uses four IPv4 NOP option bytes (`01 01 01 01`, IHL 6); a **1** uses eight NOP bytes (`01 01 01 01 01 01 01 01`, IHL 7). Both values send a packet. The ICMP payload contains only `IPOPTLAB`, a random trial UUID, a sequence number, and the expected packet count. It contains **no message bit**. This is explicit experimental bookkeeping, and means the setup is a controlled channel measurement rather than a claim of stealth against an observer who reads ICMP payloads.

**Why this encoding:** In the first September 22 lab probes, Hermes sent `01 01 00 00` (NOP, NOP, EOL, padding) and Apollo received `01 01 01 01` for the same ICMP ID 516/sequence 2; the option bytes changed while crossing Sophos. A separate eight-NOP probe (sequence 3) arrived intact at Apollo. This is an observed property of the baseline path, not proof that a security rule intentionally detected the channel. The revised experiment uses the four- versus eight-NOP option length. Verify both values with the first full trial before drawing conclusions about reliability.

## Start here: what you actually need to do

**You do not need to edit any Python code.** The scripts handle the sending, recording, comparison, CSV export, and graphs. Your work is to identify the two lab VMs, enable the controller to reach them, and change Sophos between sets of trials.

### First session: get one trial working

1. **Choose your three machines.** Sender VM transmits; receiver VM captures; controller runs `run_experiment.py` and keeps the results. The controller can be your laptop or another VM that can SSH into both lab VMs. Sophos should sit on the path between sender and receiver.
2. **Write down four values:** the sender VM IP, receiver VM IP, receiver VM capture interface (`ip -br addr` on the receiver), and the SSH name/address for each VM. If you reach the VMs through Proxmox or a jump host, configure SSH `ProxyJump` aliases first and use the aliases as `--sender` and `--receiver`.
3. **Confirm access:** from the controller, SSH into each VM without an interactive password prompt. Both VMs have Scapy 2.7.0 in `/root/covert-lab/.venv/bin/python` as checked in this lab; pass that path as `--remote-python`. The controller's own system Python can run the analyzer.
4. **Confirm raw-packet permission:** the default controller runs `sudo -n` remotely. Your current interactive `sudo` password prompt means this automated mode is **not yet ready**. It needs one-time, carefully scoped noninteractive access to the required lab commands. Alternatively use `--elevation none` if the SSH account already has raw-packet privileges (for example, a separately configured privileged lab account). Do not put sudo passwords in commands, files, or command-line arguments.
5. **Run only one short trial:** use `--message A --trials 1 --controls 1` in the command below. It produces one covert trial and one of each control traffic type. Inspect the resulting `sent.pcap` and `received.pcap`. Confirm the sender-to-receiver path really traverses Sophos; seeing packets at the receiver by itself does not prove that.

You do **not** need to configure a Sophos defense for this first run. Start with a baseline where the relevant traffic is allowed. If an options packet is already blocked, record that as the baseline finding and inspect Sophos logs.

### Later sessions: compare defenses

Keep the same message, interval, IPs, and topology. Run several baseline trials, change **one** Sophos setting, and run the same trials with a new `--condition` name. The scripts calculate packet loss, bit errors, message reconstruction, and throughput. Your remaining manual task is to review Sophos logs and mark security alerts, firewall drops, and rule matches in `evidence.csv`, with a log or screenshot reference. Then rerun the analyzer and plotting commands below.

**If any of the four values or SSH/Scapy setup is uncertain, stop at step 2.** The first concrete task is to identify the sender IP, receiver IP, and receiver interface. The longer sections below are reference material for after those are known.

## First live trial with interactive `sudo`

This path works while `sudo` still prompts for a password. Put the **latest** `receiver.py` in `/home/apollo/` and `sender.py` in `/home/hermes/`. Keep the full folder on the Proxmox host for `run_experiment.py` and `analyze.py`. Use the same UUID on both VMs. This sample UUID is for **one first trial only**; use a new UUID for each later manual trial.

Start on **Apollo** and wait for `READY`:

```bash
sudo /root/covert-lab/.venv/bin/python /home/apollo/receiver.py \
  --trial-id 11111111-1111-4111-8111-111111111111 \
  --iface ens18 --src 192.168.10.10 --dst 192.168.20.10 \
  --duration 60 \
  --out /tmp/ipv4-options-lab/data/11111111-1111-4111-8111-111111111111/rx
```

Then on **Hermes**, send the one-byte message `A` (eight bits):

```bash
sudo /root/covert-lab/.venv/bin/python /home/hermes/sender.py \
  --trial-id 11111111-1111-4111-8111-111111111111 \
  --src 192.168.10.10 --dst 192.168.20.10 \
  --message A --interval 0.25 \
  --out /tmp/ipv4-options-lab/data/11111111-1111-4111-8111-111111111111/tx
```

The receiver records what arrived when the 60-second window closes. The VMs save `sent.json`, `received.json`, and their own PCAPs. A `sent: 8` or `received: 8` count alone does **not** prove every bit is correct. The newer receiver also supports `--expected-packets 8` to stop early if all eight unique positions arrive; omitting it works with previously copied receivers.

After both commands finish, run this on **Proxmox** from its unpacked project folder. SCP can prompt for your normal VM passwords; no password is stored. This command fetches both logs and PCAPs, verifies the UUID, writes a trial manifest, and runs the analyzer:

```bash
python3 /root/ipv4_options_lab/run_experiment.py \
  --collect-trial 11111111-1111-4111-8111-111111111111 \
  --sender hermes@192.168.10.10 --receiver apollo@192.168.20.10 \
  --sender-ip 192.168.10.10 --receiver-ip 192.168.20.10 --receiver-iface ens18 \
  --condition baseline --defense-note none --message A --interval 0.25 \
  --run-dir /root/ipv4_options_lab/experiments/first-probe
```

Read `trials/<UUID>/results.json` for the decoded `A`, missing sequences, option changes, and all trial metrics; `trials.csv` and `summary.csv` are ready for later plots. Alert evidence stays `unknown` until Sophos logs have actually been reviewed. If SCP reports permission denied on VM output files, change their ownership on that VM with `sudo chown -R hermes:hermes /tmp/ipv4-options-lab/data/<UUID>/tx` or the analogous `apollo:apollo .../rx`, then rerun the collection command. Do this only for your own trial's output folder.

The five scripts are `sender.py`, `receiver.py`, `analyze.py`, `run_experiment.py`, and `plot_results.py`. The first two run on the sender and receiver VMs; the controller copies them automatically. The last three run on the controller. Python 3.10+, Scapy on both VMs, OpenSSH client, and optional Matplotlib on the controller are required.

## One-time setup

1. Use **only the isolated, authorized lab**. Confirm sender and receiver are on separate routed networks and traffic actually crosses Sophos. Capture on each side of Sophos or consult route and firewall counters to establish the path. The receiver capture alone cannot prove the path.
2. On both VMs install Scapy (`python3 -m pip install scapy` in a suitable Python environment). Install Matplotlib on the controller (`python3 -m pip install matplotlib`) if you want figures. Point `--remote-python` to the Python interpreter with Scapy. The same path must exist on both VMs.
3. Set up key-based SSH from the controller to both VMs and accept their host keys normally. Check `ssh -o BatchMode=yes user@sender true` and likewise for the receiver. The default controller mode runs `sudo -n` on both VMs for raw packets, so preconfigure **only the needed lab accounts** to run those commands without a password. Alternatively choose `--elevation none` when the SSH accounts already have raw-packet privileges. Do not grant broad passwordless privileges on shared/production machines.
4. Identify the sender and receiver VM IP addresses and the **receiver's** interface (`ip -br addr`). Ensure the VM OS firewall allows this lab traffic and Sophos initially forwards it. No internet access is needed for the traffic itself.
5. Before a full run, try one covert trial and inspect both PCAPs. If the receiving VM sees no packet, first inspect routing, firewall logs, and interface selection. You can open `sent.pcap` and `received.pcap` in Wireshark or tcpdump; confirm IPv4 options survive both sides.

## Run baseline and defense trials

From the controller's copy of this folder, substitute your actual VM values:

```bash
python3 run_experiment.py \
  --sender hermes@192.168.10.10 --receiver apollo@192.168.20.10 \
  --sender-ip 192.168.10.10 --receiver-ip 192.168.20.10 \
  --receiver-iface ens18 --remote-python /root/covert-lab/.venv/bin/python \
  --condition baseline --defense-note none \
  --message 'Header test' --interval 0.1 --trials 3 --controls 1 \
  --run-dir experiments/ipv4-options
```

The IPs, names, and interface above match your lab; the controller must be able to SSH to them, and one-time noninteractive raw-packet permissions must be configured first. The controller copies scripts to `/tmp/ipv4-options-lab` on each VM, starts the receiver before sending, and downloads packet logs and PCAPs. One control pair consists of the same number of ICMP packets with (a) a constant valid NOP option and (b) no IPv4 options. Controls are synthetic lab traffic, not a representative sample of all legitimate network traffic. The controller reanalyzes completed trials and leaves incomplete trial folders untouched. A unique UUID prevents trials from mixing.

After changing **one** Sophos rule or inspection setting, rerun the same command with `--condition sophos_rule_1 --defense-note 'rule 123 enabled'`. Optionally use `--config-file exported-rule.txt` to save an exact configuration snapshot and its SHA-256 hash. Keep message, interval, addresses, and topology the same. The result directory may hold both conditions. The controller does **not** change Sophos settings for you.

The fixed capture window is approximately `bit_count × interval + grace + 8` seconds per trial; three covert trials and one pair of controls take several minutes. `--grace` defaults to 3 seconds. A control trial uses the same packet count and interval as a covert trial.

## Review alert evidence

The controller creates `evidence.csv` with one row per complete trial and `unknown` values. For each trial, review the corresponding **Sophos security events**, firewall drops, and rule logs for that trial's time, source, destination, and UUID where available. Fill `security_alert`, `firewall_drop`, and `rule_match` independently with `yes`, `no`, or `unknown`; add the log export path, event ID, screenshot reference, or review note to `evidence_reference`. Set `no` **only** after reviewing relevant logs with logging enabled. A drop or rule hit by itself is not a security alert. You can add exported Sophos logs alongside your run; this script intentionally makes no assumptions about their version-specific format.

Then recompute results and make a paper-ready graph:

```bash
python3 analyze.py --run-dir experiments/ipv4-options
python3 plot_results.py --run-dir experiments/ipv4-options
```

`trials.csv` has one row per trial; `summary.csv` has one row per condition and traffic class. `figures/header_channel.png` and the vector `figures/header_channel.pdf` compare message reconstruction, packet loss, and correct bit goodput across conditions, with trial points over bars. Put the PDF into your paper or recreate plots directly from the CSV in Matplotlib. Graphs depict measured data only, never sample values.

## Definitions and interpretation

| Measure | Definition |
| --- | --- |
| Packet loss | Sent sequence numbers absent at receiver / sent packets. Unmatched, duplicate, and out-of-range arrivals are recorded separately. |
| Option modification | Matched packets whose option bytes differ from the sender's serialized packet. Expected routed TTL and IPv4 checksum changes do not count. |
| Bit erasure | Missing packet or unrecognized option pattern. Divided by sent bits in the summary. |
| Observed BER | Wrong decoded values / successfully decoded values; **undefined** if none decoded. Erasures are reported separately, not counted as flipped bits. |
| Message success | All packets arrived, each bit decoded correctly, and the whole message reconstructed. |
| Goodput | Correct decoded bits / (`sender_duration_seconds` + grace), in bits/s. This is a conservative fixed trial window that includes end-of-trial waiting, but excludes SSH setup. |
| Detection rate | Security-alert `yes` / reviewed (`yes` or `no`) covert trials. False-positive rate uses reviewed benign trials by traffic class. Unknown evidence stays out of both denominators. |

`trials/*/results.json` retains a reconstructed bitstring with `?` for erasures and matched packet details. `manifest.json` records the trial configuration and clock time. Do not subtract monotonic timestamps across VMs; each VM's monotonic clock is independent. If a defense drops packets, packet capture and Sophos logs together help distinguish filtering from loss. A firewall rule match alone does not establish that Sophos recognized a covert channel.

**Limitations:** IPv4 options can be dropped by routers even at baseline; this is a measured finding, not a script failure. Some captures may include retransmitted/duplicated experiment packets; duplicates are counted without guessing which is canonical. Packet sequence numbers reside in overt ICMP bookkeeping, so channel capacity and detectability differ from a fully unmarked deployment. The controller requires SSH, Scapy, raw-packet privileges, and an unchanged route during comparable trials. No live Sophos integration is claimed; alert review is the deliberate manual step.
