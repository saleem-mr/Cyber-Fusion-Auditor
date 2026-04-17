# 🛡️ Cyber Fusion Auditor v4.0

<p align="center">
  <img src="https://github.com/saleem-mr/Cyber-Fusion-Auditor/actions/workflows/python-app.yml/badge.svg" alt="Build Status">
  <img src="https://img.shields.io/github/stars/saleem-mr/Cyber-Fusion-Auditor?style=for-the-badge&color=gold" alt="GitHub Stars">
  <img src="https://img.shields.io/github/forks/saleem-mr/Cyber-Fusion-Auditor?style=for-the-badge&color=silver" alt="GitHub Forks">
  <img src="https://img.shields.io/github/license/saleem-mr/Cyber-Fusion-Auditor?style=for-the-badge" alt="License">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python" alt="Python Version">
  <img src="https://img.shields.io/badge/Stealth-Tor%20Enabled-purple?style=flat-square&logo=tor-browser" alt="Stealth">
  <img src="https://img.shields.io/badge/Status-Stable-green?style=flat-square" alt="Status">
</p>

---

> **The Omnipotent Nexus of SEO Intelligence and Cyber-Security Auditing.**

**Cyber Fusion** is a proprietary, high-performance engine designed for webmasters and security researchers. It merges real-time SEO intelligence with deep-scan security heuristics to deliver a comprehensive domain assessment in a single, beautiful CLI interface.

---

## 📋 Table of Contents
- [🚀 Key Features](#-key-features)
- [📸 Preview](#-preview)
- [🛠️ Installation](#️-installation)
- [📖 Usage](#-usage)
- [🤝 Contributing](#-contributing)
- [🛡️ Security](#️-security)
- [⚠️ Disclaimer](#️-disclaimer)
- [📜 License](#-license)

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
║ TARGET: https://target-domain.com                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌── BASIC SEO ─────────────────────────────────────────────────────────────────┐
│ ● Title tag
│   └─ Your title length is ideal. | Found: Professional Platform...
│ ● Meta Description
│   └─ Found highly optimized description.
│ ● Heading hierarchy
│   └─ Structure is valid. | Tree: H1 > H2 > H3
│ ● Canonical tag
│   └─ Self-referencing canonical tag is present.
└──────────────────────────────────────────────────────────────────────────────┘

┌── CONTENT ───────────────────────────────────────────────────────────────────┐
│ ● Word Count
│   └─ Count: 1,240 words. (Optimal for ranking)
│ ● H1 Heading
│   └─ Found 1 H1 tag. (Perfect)
│ ● Readability
│   └─ Avg: 14.2 w/s. (Excellent clarity)
│ ● H2 Headings
│   └─ Found 8 H2 tags. (Well structured)
└──────────────────────────────────────────────────────────────────────────────┘

┌── FINAL SCORE ───────────────────────────────────────────────────────────────┐
│ ██████████████████████████████████████░░ 96%
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Installation

### 1. Prerequisites
Ensure you have **Python 3.8+** and **Tor** installed on your system.

#### Linux (Debian/Ubuntu)
```bash
sudo apt update && sudo apt install tor torsocks -y
```

#### macOS
```bash
brew install tor
```

### 2. Setup
Clone the repository and install the high-performance dependencies:

```bash
git clone https://github.com/saleem-mr/Cyber-Fusion-Auditor.git
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

## 🤝 Contributing
Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**. Please see our [Contributing Guide](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).

---

## 🛡️ Security
If you discover a security vulnerability, please refer to our [Security Policy](SECURITY.md).

---

## ⚠️ Disclaimer

**FOR AUTHORIZED AUDITING ONLY.**
This tool is designed for educational purposes and for webmasters to audit their own domains. Unauthorized scanning of third-party domains may be illegal in your jurisdiction. Use with absolute responsibility.

---

## 📜 License
Distributed under the **MIT License**. See `LICENSE` for more information.

<p align="center">
  <b>Engine Crafted by Saleem.</b>
</p>
