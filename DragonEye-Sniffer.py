#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" DragonEye Sniffer - Live network traffic viewer with per-process attribution. Requirements (Windows): 1) Install Npcap -> https://npcap.com/#download (check "Install Npcap in WinPcap API-compatible Mode" during setup) 2) pip install scapy psutil 3) Run this script as Administrator (packet capture needs elevated rights) Run: python packet_sniffer.py """

import os
import sys
import csv
import time
import queue
import ctypes
import sqlite3
import traceback
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime


def is_admin() -> bool:
    try:
        if os.name == "nt":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


try:
    from scapy.all import sniff, wrpcap, get_if_list, conf, IP, IPv6, TCP, UDP, ICMP, Raw
except ImportError:
    print("ERROR: scapy is not installed. Run: pip install scapy")
    sys.exit(1)

try:
    import psutil
except ImportError:
    print("ERROR: psutil is not installed. Run: pip install psutil")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Build a clean, human-readable interface list (fixes the "10 confusing NPF
# device names" issue). Only interfaces that currently have an IPv4 address
# are listed, since those are the only ones actually carrying traffic.
# ---------------------------------------------------------------------------
def get_interface_choices():
    """Returns a list of (label, iface_for_scapy) tuples."""
    choices = []
    if sys.platform.startswith("win"):
        try:
            from scapy.arch.windows import get_windows_if_list
            for info in get_windows_if_list():
                ips = info.get("ips", []) or []
                ipv4 = next((ip for ip in ips if "." in ip and not ip.startswith("169.254")), None)
                if not ipv4:
                    continue  # skip adapters with no real IPv4 (VPN stubs, disabled NICs, etc.)
                name = info.get("name") or info.get("description") or "Unknown"
                label = f"{name} ({ipv4})"
                try:
                    iface_obj = conf.ifaces.dev_from_name(name)
                except Exception:
                    iface_obj = name
                choices.append((label, iface_obj))
        except Exception:
            pass
    if not choices:
        # Linux / macOS, or a fallback if the Windows-specific lookup failed
        for name in get_if_list():
            choices.append((name, name))
    return choices


# ---------------------------------------------------------------------------
# Port -> process name mapping, refreshed in the background every 2 seconds
# ---------------------------------------------------------------------------
class ProcessMapper:
    def __init__(self):
        self._map = {}
        self._lock = threading.Lock()
        self._running = False

    def start(self):
        self._running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            self._refresh()
            time.sleep(2)

    def _refresh(self):
        new_map = {}
        try:
            for conn in psutil.net_connections(kind="inet"):
                if not conn.laddr:
                    continue
                proto = "TCP" if conn.type == 1 else "UDP"
                pname = "Unknown"
                if conn.pid:
                    try:
                        pname = psutil.Process(conn.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pname = f"PID:{conn.pid}"
                new_map[(proto, conn.laddr.port)] = pname
        except (psutil.AccessDenied, PermissionError):
            pass
        with self._lock:
            self._map = new_map

    def lookup(self, proto: str, sport: int, dport: int) -> str:
        with self._lock:
            for port in (sport, dport):
                name = self._map.get((proto, port))
                if name:
                    return name
        return "System/Unknown"


# ---------------------------------------------------------------------------
# One captured packet, pre-processed into simple fields for display
# ---------------------------------------------------------------------------
def hex_ascii_dump(data: bytes, width: int = 16, max_bytes: int = 512) -> str:
    """Classic hex+ASCII view (like Wireshark's bottom pane), so raw bytes are readable instead of printing as garbled symbols."""
    data = data[:max_bytes]
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f" {i:04x} {hex_part} {ascii_part}")
    return "\n".join(lines)


class PacketInfo:
    __slots__ = ("no", "time", "src", "dst", "proto", "length",
                 "sport", "dport", "process", "info", "scapy_pkt")

    def __init__(self, no, scapy_pkt, mapper: ProcessMapper):
        self.no = no
        self.time = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.scapy_pkt = scapy_pkt
        self.length = len(scapy_pkt)
        self.src, self.dst, self.proto = "-", "-", "OTHER"
        self.sport, self.dport = 0, 0

        if scapy_pkt.haslayer(IP):
            self.src, self.dst = scapy_pkt[IP].src, scapy_pkt[IP].dst
        elif scapy_pkt.haslayer(IPv6):
            self.src, self.dst = scapy_pkt[IPv6].src, scapy_pkt[IPv6].dst

        if scapy_pkt.haslayer(TCP):
            self.proto = "TCP"
            self.sport, self.dport = scapy_pkt[TCP].sport, scapy_pkt[TCP].dport
        elif scapy_pkt.haslayer(UDP):
            self.proto = "UDP"
            self.sport, self.dport = scapy_pkt[UDP].sport, scapy_pkt[UDP].dport
        elif scapy_pkt.haslayer(ICMP):
            self.proto = "ICMP"

        self.process = mapper.lookup(self.proto, self.sport, self.dport)

        if scapy_pkt.haslayer(Raw):
            try:
                payload = bytes(scapy_pkt[Raw].load)
                text = payload[:80].decode("utf-8", errors="replace")
                self.info = f"Payload({len(payload)}B): {text}"
            except Exception:
                self.info = f"Payload({len(scapy_pkt[Raw].load)}B)"
        else:
            self.info = scapy_pkt.summary()

    def detail_text(self) -> str:
        """A plain-English, layer-by-layer breakdown of exactly what this packet is doing — replaces scapy's raw dump, which is hard to read."""
        sp = self.scapy_pkt
        L = []
        L.append(f"Packet #{self.no} | captured at {self.time} | {self.length} bytes total")
        L.append("=" * 70)

        # --- Network layer (who is talking to whom) ---
        if sp.haslayer(IP):
            ip = sp[IP]
            L.append("NETWORK LAYER (IPv4) — where the packet is going")
            L.append(f" From (source): {ip.src}")
            L.append(f" To (destination): {ip.dst}")
            L.append(f" Time-to-live (TTL): {ip.ttl} (hops left before it's discarded)")
        elif sp.haslayer(IPv6):
            ip6 = sp[IPv6]
            L.append("NETWORK LAYER (IPv6) — where the packet is going")
            L.append(f" From (source): {ip6.src}")
            L.append(f" To (destination): {ip6.dst}")
        L.append("")

        # --- Transport layer (which conversation / connection) ---
        if sp.haslayer(TCP):
            tcp = sp[TCP]
            flag_names = {"F": "FIN (closing)", "S": "SYN (opening)", "R": "RST (reset)",
                          "P": "PSH (push data)", "A": "ACK (acknowledge)",
                          "U": "URG (urgent)", "E": "ECE", "C": "CWR"}
            active = [flag_names[f] for f in str(tcp.flags) if f in flag_names]
            L.append("TRANSPORT LAYER (TCP) — which connection this belongs to")
            L.append(f" Source port: {tcp.sport}")
            L.append(f" Destination port: {tcp.dport}")
            L.append(f" What's happening: {', '.join(active) if active else '(data segment)'}")
            L.append(f" Sequence number: {tcp.seq}")
            L.append(f" Acknowledgement #: {tcp.ack}")
        elif sp.haslayer(UDP):
            udp = sp[UDP]
            L.append("TRANSPORT LAYER (UDP) — which connection this belongs to")
            L.append(f" Source port: {udp.sport}")
            L.append(f" Destination port: {udp.dport}")
        L.append("")

        # --- Payload (the actual content) ---
        if sp.haslayer(Raw):
            payload = bytes(sp[Raw].load)
            is_encrypted = self.sport == 443 or self.dport == 443
            L.append(f"PAYLOAD — the actual data inside this packet ({len(payload)} bytes)")
            if is_encrypted:
                L.append(" This is HTTPS traffic, so the content is TLS-encrypted.")
                L.append(" The bytes below are scrambled ON PURPOSE — that's HTTPS")
                L.append(" protecting your data, not a problem with the capture.")
                L.append(" Only the sender/receiver can decrypt this.")
            else:
                try:
                    text_preview = payload.decode("utf-8")
                    if text_preview.isprintable() or "\n" in text_preview:
                        L.append(" Readable text found in this packet:")
                        L.append(" " + text_preview[:300].replace("\n", "\n "))
                        L.append("")
                except UnicodeDecodeError:
                    pass
            L.append("")
            L.append(" Raw bytes (hex | text):")
            L.append(hex_ascii_dump(payload))
        else:
            L.append("PAYLOAD — none")
            L.append(" This packet carries no data — it's a header-only control")
            L.append(" packet (e.g. a TCP handshake or acknowledgement).")

        return "\n".join(L)

    def searchable(self) -> str:
        return f"{self.src} {self.dst} {self.proto} {self.process} {self.info}".lower()


class PacketDB:
    def __init__(self, path="packets.db"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute(""" CREATE TABLE IF NOT EXISTS packets ( id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, src TEXT, dst TEXT, proto TEXT, length INTEGER, sport INTEGER, dport INTEGER, process TEXT, info TEXT ) """)
        self.conn.commit()

    def insert(self, p: PacketInfo):
        self.conn.execute(
            "INSERT INTO packets (time, src, dst, proto, length, sport, dport, process, info) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (p.time, p.src, p.dst, p.proto, p.length, p.sport, p.dport, p.process, p.info)
        )

    def close(self):
        self.conn.commit()
        self.conn.close()


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------
class SnifferApp(tk.Tk):
    BG = "#12141c"
    PANEL = "#1b1e2b"
    ACCENT = "#5eead4"
    TEXT = "#e8e8ef"
    MUTED = "#8b90a5"
    PROTO_COLORS = {"TCP": "#5eead4", "UDP": "#fbbf70", "ICMP": "#f78ea7", "OTHER": "#8b90a5"}

    def __init__(self):
        super().__init__()
        self.title("🐉 DragonEye Sniffer — Network Analyzer")
        self.geometry("1320x800")
        self.configure(bg=self.BG)
        self.minsize(1050, 650)

        self.mapper = ProcessMapper()
        self.mapper.start()

        self.capturing = False
        self.packet_counter = 0
        self.packets: list[PacketInfo] = []
        self.gui_queue: queue.Queue = queue.Queue()
        self.iface_choices = get_interface_choices()
        self.iface_map = dict(self.iface_choices)

        self._build_style()
        self._build_layout()
        self.after(120, self._drain_queue)

        if not self.iface_choices:
            self.after(300, lambda: messagebox.showwarning(
                "No network interface found",
                "No active network interface was detected.\n\n"
                "Make sure Npcap is installed (https://npcap.com/#download) "
                "and that you are connected to a network."
            ))

    # ---------------------- styling ----------------------
    def _build_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", background=self.PANEL, fieldbackground=self.PANEL,
                         foreground=self.TEXT, rowheight=25, borderwidth=0, font=("Consolas", 10))
        style.configure("Treeview.Heading", background=self.BG, foreground=self.ACCENT,
                         font=("Segoe UI Semibold", 10))
        style.map("Treeview", background=[("selected", self.ACCENT)], foreground=[("selected", "#0b0c10")])
        style.configure("TButton", background=self.ACCENT, foreground="#0b0c10",
                         font=("Segoe UI", 10, "bold"), padding=7, borderwidth=0)
        style.map("TButton", background=[("active", "#3fd8c4"), ("disabled", "#3a3f52")])
        style.configure("TLabel", background=self.BG, foreground=self.TEXT, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=self.BG, foreground=self.MUTED, font=("Segoe UI", 9))
        style.configure("Status.TLabel", background=self.BG, foreground=self.ACCENT, font=("Segoe UI", 10, "bold"))
        style.configure("TEntry", fieldbackground=self.PANEL, foreground=self.TEXT, insertcolor=self.TEXT)
        style.configure("TCombobox", fieldbackground=self.PANEL, foreground=self.TEXT)
        style.configure("TFrame", background=self.BG)

    # ---------------------- layout ----------------------
    def _build_layout(self):
        header = ttk.Frame(self, padding=(14, 12, 14, 6))
        header.pack(fill="x")
        ttk.Label(header, text="🐉 DragonEye Sniffer", font=("Segoe UI Semibold", 15)).pack(side="left")
        ttk.Label(header, text=" live capture • per-process attribution • export",
                  style="Muted.TLabel").pack(side="left", padx=(10, 0))

        top = ttk.Frame(self, padding=(14, 4))
        top.pack(fill="x")

        ttk.Label(top, text="Interface:").grid(row=0, column=0, padx=(0, 6), sticky="w")
        self.iface_var = tk.StringVar()
        labels = [c[0] for c in self.iface_choices]
        self.iface_combo = ttk.Combobox(top, textvariable=self.iface_var, values=labels, width=42, state="readonly")
        if labels:
            self.iface_combo.current(0)
        self.iface_combo.grid(row=0, column=1, padx=(0, 14))
        ttk.Button(top, text="⟳ Refresh", width=10, command=self._refresh_interfaces).grid(row=0, column=2, padx=(0, 20))

        bpf_row = ttk.Frame(top)
        bpf_row.grid(row=0, column=3, padx=(0, 20), sticky="w")
        ttk.Label(bpf_row, text="Capture filter (optional):").pack(side="left")
        ttk.Button(bpf_row, text="?", width=2, command=self._show_bpf_help).pack(side="left", padx=(4, 8))
        self.bpf_var = tk.StringVar()
        bpf_entry = ttk.Entry(top, textvariable=self.bpf_var, width=26)
        bpf_entry.grid(row=0, column=4, padx=(0, 20))
        self._set_placeholder(bpf_entry, self.bpf_var, "e.g. tcp port 443")

        ttk.Label(top, text="Live search (src / dst / process / info):").grid(row=0, column=5, padx=(0, 6), sticky="w")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self._apply_display_filter())
        ttk.Entry(top, textvariable=self.search_var, width=24).grid(row=0, column=6)

        btns = ttk.Frame(self, padding=(14, 6))
        btns.pack(fill="x")
        self.start_btn = ttk.Button(btns, text="▶ Start Capture", command=self.start_capture)
        self.start_btn.pack(side="left", padx=(0, 6))
        self.stop_btn = ttk.Button(btns, text="⏸ Stop", command=self.stop_capture, state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        ttk.Button(btns, text="🗑 Clear", command=self.clear_packets).pack(side="left", padx=6)
        ttk.Button(btns, text="💾 Save PCAP (Wireshark)", command=self.save_pcap).pack(side="left", padx=6)
        ttk.Button(btns, text="📄 Save CSV", command=self.save_csv).pack(side="left", padx=6)
        ttk.Button(btns, text="🗄 Save to Database", command=self.save_to_db).pack(side="left", padx=6)

        self.status_var = tk.StringVar(value="Ready — select an interface and press Start")
        ttk.Label(btns, textvariable=self.status_var, style="Status.TLabel").pack(side="right", padx=6)

        mid = ttk.Frame(self, padding=(14, 6))
        mid.pack(fill="both", expand=True)

        cols = ("no", "time", "src", "dst", "proto", "length", "process", "info")
        headers = {"no": "#", "time": "Time", "src": "Source", "dst": "Destination",
                   "proto": "Proto", "length": "Len", "process": "Process", "info": "Info"}
        widths = {"no": 55, "time": 100, "src": 160, "dst": 160,
                  "proto": 65, "length": 60, "process": 150, "info": 420}

        tree_frame = ttk.Frame(mid)
        tree_frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings")
        for col in cols:
            self.tree.heading(col, text=headers[col])
            self.tree.column(col, width=widths[col], anchor="w")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select_packet)
        for proto, color in self.PROTO_COLORS.items():
            self.tree.tag_configure(proto, foreground=color)

        bottom = ttk.Frame(self, padding=(14, 6, 14, 12))
        bottom.pack(fill="both", expand=False)
        ttk.Label(bottom, text="Packet details:", style="Muted.TLabel").pack(anchor="w")
        self.detail_text = tk.Text(bottom, height=12, bg=self.PANEL, fg=self.TEXT,
                                    insertbackground=self.TEXT, font=("Consolas", 9),
                                    relief="flat", padx=8, pady=6)
        self.detail_text.pack(fill="both", expand=True, pady=(4, 0))

    def _set_placeholder(self, entry, var, text):
        """Shows a greyed-out example inside an empty entry box, so the user immediately understands what to type there."""
        var.set(text)
        entry.configure(foreground=self.MUTED)

        def on_focus_in(_e):
            if var.get() == text:
                var.set("")
                entry.configure(foreground=self.TEXT)

        def on_focus_out(_e):
            if not var.get().strip():
                var.set(text)
                entry.configure(foreground=self.MUTED)

        entry.bind("<FocusIn>", on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)

    def _get_bpf_filter(self):
        """Returns the capture filter text, or None if it's empty/placeholder."""
        text = self.bpf_var.get().strip()
        if not text or text == "e.g. tcp port 443":
            return None
        return text

    def _show_bpf_help(self):
        messagebox.showinfo(
            "What is the Capture Filter?",
            "This box decides WHICH packets get captured in the first place — "
            "it is applied before anything reaches the table.\n\n"
            "It is NOT just a port number — it's a small expression (BPF syntax) "
            "that can match protocol, IP address, port, or a combination.\n\n"
            "Examples:\n"
            " tcp port 443 → only HTTPS traffic\n"
            " udp port 53 → only DNS traffic\n"
            " host 8.8.8.8 → only traffic to/from that IP\n"
            " tcp and port 80 → only HTTP (TCP, port 80)\n\n"
            "Leave it empty to capture EVERYTHING on the interface.\n\n"
            "Difference from 'Live search': the search box on the right doesn't "
            "change what's captured — it only narrows what's shown in the table, "
            "instantly, without restarting the capture."
        )

    def _refresh_interfaces(self):
        self.iface_choices = get_interface_choices()
        self.iface_map = dict(self.iface_choices)
        labels = [c[0] for c in self.iface_choices]
        self.iface_combo["values"] = labels
        if labels:
            self.iface_combo.current(0)
        self.status_var.set(f"Found {len(labels)} active interface(s)")

    # ---------------------- capture logic ----------------------
    def start_capture(self):
        if not is_admin():
            messagebox.showwarning(
                "Administrator rights required",
                "Packet capture needs elevated rights.\n"
                "Please re-launch this script as Administrator."
            )
            return
        if not self.iface_var.get():
            messagebox.showerror("Error", "Please select a network interface.")
            return

        self.capturing = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_var.set("Capturing... (0 packets)")

        threading.Thread(target=self._sniff_worker, daemon=True).start()

    def _sniff_worker(self):
        iface = self.iface_map.get(self.iface_var.get())
        bpf = self._get_bpf_filter()
        try:
            sniff(
                iface=iface,
                filter=bpf,
                prn=self._on_packet_captured,
                stop_filter=lambda p: not self.capturing,
                store=False,
            )
        except Exception:
            self.gui_queue.put(("error", traceback.format_exc()))

    def _on_packet_captured(self, scapy_pkt):
        self.packet_counter += 1
        info = PacketInfo(self.packet_counter, scapy_pkt, self.mapper)
        self.gui_queue.put(("packet", info))

    def stop_capture(self):
        self.capturing = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_var.set(f"Stopped — {len(self.packets)} packet(s) captured")

    def clear_packets(self):
        self.packets.clear()
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.packet_counter = 0
        self.detail_text.delete("1.0", "end")
        self.status_var.set("Cleared")

    # ---------------------- GUI refresh ----------------------
    def _drain_queue(self):
        try:
            while True:
                kind, payload = self.gui_queue.get_nowait()
                if kind == "packet":
                    self._add_packet_row(payload)
                elif kind == "error":
                    messagebox.showerror(
                        "Capture error",
                        "Could not start capturing on this interface:\n\n"
                        f"{payload}\n\n"
                        "Common causes: Npcap not installed, wrong interface selected, "
                        "or the app is not running as Administrator."
                    )
                    self.stop_capture()
        except queue.Empty:
            pass
        self.after(120, self._drain_queue)

    def _add_packet_row(self, p: PacketInfo):
        self.packets.append(p)
        if self._passes_display_filter(p):
            self.tree.insert("", "end", iid=str(p.no),
                              values=(p.no, p.time, p.src, p.dst, p.proto, p.length, p.process, p.info),
                              tags=(p.proto,))
            self.tree.see(str(p.no))
        if self.capturing:
            self.status_var.set(f"Capturing... ({len(self.packets)} packets)")

    def _passes_display_filter(self, p: PacketInfo) -> bool:
        needle = self.search_var.get().strip().lower()
        return (not needle) or (needle in p.searchable())

    def _apply_display_filter(self):
        # Live, incremental filtering: capture keeps running untouched, only
        # what's shown in the table narrows down as you type.
        for row in self.tree.get_children():
            self.tree.delete(row)
        for p in self.packets:
            if self._passes_display_filter(p):
                self.tree.insert("", "end", iid=str(p.no),
                                  values=(p.no, p.time, p.src, p.dst, p.proto, p.length, p.process, p.info),
                                  tags=(p.proto,))

    def _on_select_packet(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        p = next((pk for pk in self.packets if pk.no == int(sel[0])), None)
        if not p:
            return
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("end", p.detail_text())

    # ---------------------- saving ----------------------
    def _filtered_packets(self):
        return [p for p in self.packets if self._passes_display_filter(p)]

    def save_pcap(self):
        pkts = self._filtered_packets()
        if not pkts:
            messagebox.showinfo("Nothing to save", "There are no packets to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("Wireshark PCAP", "*.pcap")])
        if not path:
            return
        wrpcap(path, [p.scapy_pkt for p in pkts])
        messagebox.showinfo("Saved", f"{len(pkts)} packet(s) saved to:\n{path}\n\nOpen it directly in Wireshark.")

    def save_csv(self):
        pkts = self._filtered_packets()
        if not pkts:
            messagebox.showinfo("Nothing to save", "There are no packets to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["No", "Time", "Source", "Destination", "Protocol", "Length",
                              "SrcPort", "DstPort", "Process", "Info"])
            for p in pkts:
                writer.writerow([p.no, p.time, p.src, p.dst, p.proto, p.length,
                                  p.sport, p.dport, p.process, p.info])
        messagebox.showinfo("Saved", f"{len(pkts)} packet(s) saved to:\n{path}")

    def save_to_db(self):
        pkts = self._filtered_packets()
        if not pkts:
            messagebox.showinfo("Nothing to save", "There are no packets to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".db", filetypes=[("SQLite DB", "*.db")])
        if not path:
            return
        db = PacketDB(path)
        for p in pkts:
            db.insert(p)
        db.close()
        messagebox.showinfo("Saved", f"{len(pkts)} packet(s) saved to database:\n{path}")

    def on_close(self):
        self.capturing = False
        self.mapper.stop()
        self.destroy()


if __name__ == "__main__":
    if not is_admin():
        print("=" * 60)
        print("WARNING: not running as Administrator.")
        print("Packet capture requires elevated rights on Windows.")
        print("=" * 60)

    app = SnifferApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()