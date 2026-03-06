
# SIP Vulnerability & Encryption Auditor (BASH)

A specialized reconnaissance tool for **ethical security engagements** designed to identify SIP-enabled endpoints, audit their encryption status, and detect common misconfigurations.

## 📋 Overview

This script automates the discovery and fingerprinting phase of a VoIP security audit. It differentiates between active SIP devices and standard network hardware, specifically flagging unencrypted communication channels that are vulnerable to packet sniffing (snooping).

### Key Features

* **Pre-Flight Filtering:** Automatically identifies and skips non-SIP devices to reduce log noise.
* **Encryption Analysis:** Flags Port `5060` (UDP/TCP) as a high-risk unencrypted line and Port `5061` (TLS) as encrypted.
* **Automated Fingerprinting:** Utilizes `sipvicious` to identify PBX software, hardware brands, and version strings.
* **Extension Enumeration:** Checks if internal extension ranges are "leaking" or susceptible to brute-force registration.

---

## 🚀 Getting Started

### Prerequisites

The script is optimized for **Kali Linux**. Ensure the following industry-standard tools are installed:

```bash
sudo apt update
sudo apt install nmap sipvicious -y

```

### Installation

1. Copy the `sip_audit.sh` script to your working directory.
2. Grant execution permissions:
```bash
chmod +x sip_audit.sh

```



---

## 🛠 Usage

### 1. Prepare Target List

Create a text file (e.g., `targets.txt`) with one IP address or FQDN per line:

```text
192.168.1.10
192.168.1.50
pbx.client-domain.com
10.0.0.5

```

### 2. Run the Audit

Execute the script by passing the target list as an argument:

```bash
./sip_audit.sh targets.txt

```

### 3. Review Results

The script provides real-time console output and generates a timestamped log file:
`sip_audit_results_YYYY-MM-DD.txt`

---

## 🔍 Audit Logic & Findings

| Finding | Indicator | Risk Level | Description |
| --- | --- | --- | --- |
| **Not a SIP Device** | No response on 5060/5061/5070 | **N/A** | Device ignored; no SIP services detected. |
| **Unencrypted SIP** | Port 5060 Open | 🔴 **High** | Traffic is plain text. Vulnerable to snooping, call hijacking, and MITM. |
| **Encrypted SIPS** | Port 5061 Open | 🟢 **Low** | Signaling is wrapped in TLS (Industry Best Practice). |
| **Extensions Visible** | `svwar` success | 🟡 **Medium** | Internal extension mapping is possible. Increases brute-force risk. |
| **PBX Fingerprint** | `svmap` User-Agent | 🔵 **Info** | Identifies specific hardware/software (e.g., Asterisk, Cisco, Mitel). |

---
