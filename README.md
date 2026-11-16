# Isolated Network Covert-Channel Laboratory

**Authors:** Kaleb Bacztub, Braden Vester, and Jon Walatkiewicz  
**Institution:** Purdue Polytechnic Institute, Purdue University  
**Date:** November 2026

## Overview

This repository contains the source code, orchestration suites, and empirical datasets for the **Development of an Isolated Network Covert-Channel Laboratory**. This research examines how network covert channels can be constructed, observed, and actively mitigated in a controlled enterprise virtual environment.

We evaluate an IPv4 header options storage channel, a bimodal inter-packet timing channel, and an advanced Machine Learning-assisted Statistical Mimicry channel against both commercial Intrusion Prevention Systems (Sophos Firewall) and a custom inline Layer 2 bridge known as the **Hades Active Warden**.

## Key Research Findings

1. **Commercial IPS Limitations:** Standard Sophos Intrusion Prevention System (IPS) policies failed to detect our storage and timing channels (allowing 100% message recovery). Creating custom header-drop signatures eliminated the covert traffic but caused an unacceptable **100% collateral packet loss** on legitimate option-bearing traffic.
2. **Statistical Mimicry:** By profiling organic OS telemetry (DNS/NTP) and injecting Gaussian jitter, our Statistical Mimicry channel successfully evaded statistical anomaly detection, utilizing an unsupervised 1D K-Means clustering algorithm on the receiver to achieve a 100% decoding success rate.
3. **Active Mitigation (Hades Warden):** We developed an inline active warden using Linux `nftables` and a Python NetfilterQueue daemon. By combining deterministic header normalization with a rigid FIFO packet release cadence ($\\tau=0.40s$), the warden collapsed timing variance ($\\sigma \\rightarrow 0$). This neutralized both storage and ML-decoded timing channels (0% message success) while maintaining a **0% packet loss rate** for legitimate enterprise traffic.

## Laboratory Architecture

The environment consists of five Proxmox virtual machines operating on isolated private IPv4 space:

* **Hermes (Sender - 192.168.10.10):** The covert-channel sender and Python Scapy packet generator.
* **Apollo (Receiver - 192.168.20.10):** The covert-channel receiver, packet-capture endpoint, and Domain Controller stub.
* **Hephaestus (Firewall - 192.168.10.1 / 20.1):** A Sophos Firewall appliance routing traffic between the LAN and DMZ subnets.
* **Tyche (Simulator - 192.168.10.11):** A benign traffic simulator executing multi-threaded Active Directory noise (DNS, NTP, LDAP, SMB, Kerberos) representing five distinct workstations.
* **Hades (Warden - Inline Bridge):** A transparent Layer 2 active mitigation bridge capable of real-time protocol normalization and packet pacing.

## Repository Structure

* `/ipv4\_options\_lab/` - Orchestration scripts and packet generators for the IPv4 options storage channel.
* `/ipv4\_timing\_lab/` - Source code for both the rigid bimodal timing channel and the ML-assisted statistical mimicry channel, including the K-Means decoder.
* `/warden\_lab/` - Python NetfilterQueue scripts (`run\_visible\_study.py`) powering the inline Hades Active Warden.
* `/traffic-sim/` - The Active Directory enterprise traffic simulation scripts (`trafficSim\_test.py`, `hermes\_telemetry.py`) used to generate background noise.
* `mega\_summary\_report.csv` - The aggregated 100+ trial dataset highlighting bit error rates, loss rates, and goodput across all evaluated conditions.
* `IEEE\_Letter\_Paper...pdf` - The final formatted IEEE Networking Letters manuscript detailing our findings.
* `Progress\_Report...pdf` - Detailed operational progress reports documenting the laboratory's construction and experimental phases.

## Technology Stack

* **Infrastructure:** Proxmox VE, Ubuntu Server, Sophos Firewall
* **Networking:** Scapy, `tcpdump`, `nftables`, NetfilterQueue
* **Data Science:** Python 3, `scikit-learn` (K-Means), `numpy`, `pandas`, `matplotlib`

## Disclaimer

This project is dual-use research conducted in a strictly isolated environment. All administrative passwords, firewall master keys, and private SSH keys have been scrubbed from this repository. The tools provided are intended solely for academic research and defensive engineering.

