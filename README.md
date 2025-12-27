# 🛡️ Cyber Fusion Auditor v4.0

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Stealth](https://img.shields.io/badge/Stealth-Tor%20Enabled-purple.svg)](#)

> **The Omnipotent Nexus of SEO Intelligence and Cyber-Security Auditing.**

**Cyber Fusion** is a proprietary, high-performance engine designed for webmasters and security researchers. It merges real-time SEO intelligence with deep-scan security heuristics to deliver a comprehensive domain assessment in a single, beautiful CLI interface.

---

## 🚀 Key Features

*   **⚡ Hybrid SEO Logic:** Real-time WebSocket intelligence fused with granular on-page heuristics (Word counts, Readability, Keyword density).
*   **🛡️ Cyber-Security Suite:** Proactive probing for sensitive file exposures (`.env`, `phpinfo`), technology stack leaks, and cookie hardening verification.
*   **🕸️ Stealth Anonymity:** Integrated automatic Tor management. All traffic is silently routed through the Tor network to bypass firewalls and maintain 100% anonymity.
*   **🔍 Site-Wide Crawling:** Advanced recursive engine to audit broken assets and links across your entire domain.
*   **💎 Premium CLI UX:** Professional, organized reporting with visual performance indicators and hierarchical insights.

---

## 📸 Preview

```text
╔══════════════════════════════════════════════════════════════════════════════╗
║ OMNIPOTENT MASTER AUDIT v4.0                                                 ║
║ TARGET: https://example.com                                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌── SECURITY ──────────────────────────────────────────────────────────────────┐
│ ● Sensitive Files
│   └─ Protected. Config files (.env, .git) are safe.
│ ● Information Leakage
│   └─ No tech-stack signatures leaked.
└──────────────────────────────────────────────────────────────────────────────┘

┌── FINAL SCORE ───────────────────────────────────────────────────────────────┐
│ ██████████████████████████████████████░ 98%
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Installation

### 1. Prerequisites
Ensure you have **Python 3.8+** and **Tor** installed on your system.

```bash
# Linux (Debian/Ubuntu)
sudo apt install tor torsocks
```

### 2. Setup
Clone the repository and install the high-performance dependencies:

```bash
git clone https://github.com/Saleem/Cyber-Fusion-Auditor.git
cd Cyber-Fusion-Auditor
pip install -r requirements.txt
```

---

## 📖 Usage

Run a standard audit with automatic Tor routing:
```bash
python3 cyber_fusion.py -u https://example.com
```

Perform a **Site-Wide Deep Audit** (Site-wide asset check):
```bash
python3 cyber_fusion.py -u https://example.com --deep-scan --crawl
```

### Options:
| Flag | Description |
| --- | --- |
| `-u`, `--url` | **Required.** The target URL to audit. |
| `--keywords` | Comma-separated list of SEO target keywords. |
| `--deep-scan` | Enable the broken asset and link auditor. |
| `--crawl` | Recursive mode (follows all internal links). |
| `--concurrency` | Adjust scanning speed (default is 1 for stability). |

---

## ⚠️ Disclaimer

**FOR AUTHORIZED AUDITING ONLY.**
This tool is designed for educational purposes and for webmasters to audit their own domains. Unauthorized scanning of third-party domains may be illegal in your jurisdiction. Use with absolute responsibility.

---

## 📜 License
Distributed under the **MIT License**. See `LICENSE` for more information.

**Engine Crafted by Saleem.**
