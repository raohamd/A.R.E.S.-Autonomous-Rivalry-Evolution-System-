# 🛡️ A.R.E.S. (Autonomous Rivalry & Evolution System)

> **Advanced Cyber Defense Simulation Framework**
>
> *Bridging the gap between Passive Detection (IDS) and Active Neutralization (IPS) using eBPF and AI.*

![Project Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Tech Stack](https://img.shields.io/badge/Core-eBPF%20%7C%20Python%20%7C%20Docker-blue)
![AI Integration](https://img.shields.io/badge/AI-Grok%20LLM-orange)

## 📜 Overview
**Project A.R.E.S.** establishes a containerized adversarial network designed to simulate, detect, and neutralize cyber threats in real-time. By leveraging **eBPF (Extended Berkeley Packet Filter)** for kernel-level observability, the system provides "God's Eye" visibility into host system calls.

The core innovation is the integration of an **AI "Brain" (Grok LLM)** that analyzes these system calls to determine intent. If a threat is detected (e.g., unauthorized `nmap` scanning or privilege escalation via `sudo`), A.R.E.S. automatically enters **"Hunter-Killer Mode"** and terminates the malicious process instantly.

---

## 🏗️ System Architecture
The project operates on a "Purple Team" Docker infrastructure:

* 🔴 **Red Node (Attacker):** Kali Linux container acting as the adversary.
* 🔵 **Blue Node (Defender):** Ubuntu container with eBPF privileges for forensic monitoring.
* 🎯 **Target Node (Victim):** OWASP Juice Shop serving as the vulnerability sandbox.

---

## ✨ Key Features

* **Kernel-Level Observability:** Hooks the `execve` syscall using Python BCC to intercept process execution before it completes.
* **AI-Driven Analysis:** Utilizes the **Grok API** to analyze command arguments and determine malicious intent.
* **Active Defense (IPS):** Automatically issues `SIGKILL` signals to neutralize threats in milliseconds.
* **Cross-Container Visibility:** Detects attacks originating from one container and targeting another via the host kernel.
* **Live War Room:** A **Streamlit** dashboard visualizing threat vectors, live telemetry, and neutralization logs.

---

## 🚀 Installation & Setup

### Prerequisites
* Docker & Docker Compose (V2 Plugin)
* Python 3.10+
* Linux Host (Ubuntu recommended for eBPF compatibility)

### 1. Clone the Repository
```bash
git clone https://github.com/raohamd/ARES_PROJECT.git
cd ARES_PROJECT
