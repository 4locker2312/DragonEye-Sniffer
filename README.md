# 🐉 DragonEye Sniffer – Live Network Analyzer & Process Monitor

> A lightweight, real-time desktop network packet analyzer built with **Python**, **Tkinter**, **Scapy**, and **psutil**.

---

## 📌 Overview

**DragonEye Sniffer** is an intuitive network capture and inspection tool designed for Windows/Linux. It not only captures live network packets but also correlates connections directly to active system processes (e.g., matching traffic to `chrome.exe`, `discord.exe`, etc.) and provides plain-English layer-by-layer packet breakdowns.

---

## ✨ Key Features

* **Real-Time Packet Capture:** Intercept network traffic using Scapy and Npcap.
* **Per-Process Traffic Attribution:** Maps active sockets to system processes in real-time using `psutil`.
* **Smart Interface Selection:** Automatically filters out inactive/virtual adapters to display active interfaces with IPv4 addresses.
* **BPF & Live Filtering:** Apply Berkeley Packet Filters (BPF) before capture, or use real-time live search across source, destination, process, or info fields.
* **Deep Packet Inspection:** Provides Hex + ASCII byte dumps and human-readable analysis of IPv4/IPv6, TCP, UDP, and ICMP protocols.
* **Multiple Export Formats:** Save captured traffic as `.pcap` (Wireshark compatible), `.csv`, or directly into a `.db` (SQLite Database).

---

## 🛠️ Tech Stack

* **GUI Framework:** Python `tkinter` / `ttk` (Custom Dark Theme)
* **Packet Sniffing:** `scapy`
* **Process Mapping:** `psutil`
* **Database:** `sqlite3`

---

## ⚙️ Installation & Prerequisites

### 1. Requirements (Windows)
* Install **Npcap**: [https://npcap.com/#download](https://npcap.com/#download)  
  *(Make sure to check "Install Npcap in WinPcap API-compatible Mode" during setup)*

### 2. Install Python Dependencies
```bash
pip install scapy psutil
