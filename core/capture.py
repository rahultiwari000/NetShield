import os
import platform
import queue
import random
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    from scapy.all import (
        DNS,
        DNSQR,
        ICMP,
        IP,
        IPv6,
        TCP,
        UDP,
        AsyncSniffer,
        ICMPv6EchoReply,
        ICMPv6EchoRequest,
        conf,
        get_if_list,
    )

    if platform.system() == "Windows":
        from scapy.arch.windows import get_windows_if_list
    else:
        get_windows_if_list = None

    SCAPY_AVAILABLE = True
    SCAPY_IMPORT_ERROR = ""
except Exception as exc:
    SCAPY_AVAILABLE = False
    SCAPY_IMPORT_ERROR = str(exc)

SIMULATOR_DEVICE = "__SIMULATOR__"
SIMULATOR_LABEL = "Cloud Demo / Live Traffic Simulator (No Root Required)"


def is_cloud_environment() -> bool:
    if os.environ.get("STREAMLIT_SHARING_MODE") or os.environ.get("STREAMLIT_SERVER_HEADLESS"):
        if platform.system() != "Windows":
            return True
    if os.path.exists("/mount/src"):
        return True
    return False


class PacketCapture:
    def __init__(self, packet_queue: "queue.Queue[Dict[str, Any]]"):
        self.packet_queue = packet_queue
        self.sniffer: Optional[Any] = None
        self._sim_thread: Optional[threading.Thread] = None
        self._sim_stop = threading.Event()
        self.status: str = "Stopped"
        self.mode: str = "Stopped"
        self.error_message: str = ""
        self.selected_interface_label: str = ""
        self.selected_interface_device: str = ""
        self.dropped_packets: int = 0
        self._lock = threading.Lock()

    @staticmethod
    def list_interfaces() -> List[Tuple[str, str]]:
        interfaces: List[Tuple[str, str]] = []
        seen_devices = set()

        if SCAPY_AVAILABLE:
            if platform.system() == "Windows" and get_windows_if_list is not None:
                try:
                    for iface in get_windows_if_list():
                        name = iface.get("name") or "Unknown Adapter"
                        desc = iface.get("description") or ""
                        guid = iface.get("guid") or ""
                        ips = [ip for ip in (iface.get("ips") or []) if ":" not in ip]
                        ip_str = ips[0] if ips else "No IPv4"
                        device = f"\\Device\\NPF_{guid}" if guid else name
                        if device in seen_devices:
                            continue
                        seen_devices.add(device)
                        label = f"{name} ({ip_str})" + (f" - {desc}" if desc else "")
                        interfaces.append((label, device))
                except Exception:
                    pass

            if not interfaces:
                try:
                    for dev in get_if_list():
                        if dev not in seen_devices:
                            seen_devices.add(dev)
                            interfaces.append((str(dev), str(dev)))
                except Exception:
                    pass

            if not interfaces:
                default_dev = str(conf.iface) if getattr(conf, "iface", None) else ""
                if default_dev:
                    interfaces.append((f"Default ({default_dev})", default_dev))

        if is_cloud_environment():
            interfaces.insert(0, (SIMULATOR_LABEL, SIMULATOR_DEVICE))
        else:
            interfaces.append((SIMULATOR_LABEL, SIMULATOR_DEVICE))

        return interfaces

    @staticmethod
    def _extract_metadata(pkt: Any) -> Optional[Dict[str, Any]]:
        src_ip = None
        dst_ip = None

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        else:
            return None

        now_epoch = time.time()
        ts_str = datetime.fromtimestamp(now_epoch).strftime("%H:%M:%S.%f")[:-3]
        size = len(pkt)
        protocol = "OTHER"
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        tcp_flags: Optional[str] = None
        dns_query: Optional[str] = None

        if pkt.haslayer(TCP):
            protocol = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            tcp_flags = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
        elif (
            pkt.haslayer(ICMP)
            or pkt.haslayer(ICMPv6EchoRequest)
            or pkt.haslayer(ICMPv6EchoReply)
        ):
            protocol = "ICMP"

        if pkt.haslayer(DNS):
            protocol = "DNS"
            try:
                if pkt.haslayer(DNSQR) and pkt[DNSQR].qname:
                    raw_qname = pkt[DNSQR].qname
                    dns_query = (
                        raw_qname.decode("utf-8", errors="ignore").rstrip(".")
                        if isinstance(raw_qname, bytes)
                        else str(raw_qname).rstrip(".")
                    )
            except Exception:
                dns_query = None

        return {
            "epoch": now_epoch,
            "timestamp": ts_str,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "size": size,
            "tcp_flags": tcp_flags,
            "dns_query": dns_query,
            "status": "Normal",
            "threat": None,
        }

    def _enqueue_meta(self, meta: Dict[str, Any]) -> None:
        try:
            self.packet_queue.put_nowait(meta)
        except queue.Full:
            self.dropped_packets += 1

    def _on_packet(self, pkt: Any) -> None:
        meta = self._extract_metadata(pkt)
        if meta is not None:
            self._enqueue_meta(meta)

    def _run_simulator_loop(self) -> None:
        normal_hosts = ["192.168.1.10", "192.168.1.14", "192.168.1.22", "192.168.1.35"]
        external_servers = ["142.250.190.46", "1.1.1.1", "8.8.8.8", "104.18.32.7", "52.94.236.248"]
        dns_domains = ["github.com", "docs.streamlit.io", "api.openai.com", "pypi.org", "cloudflare.com"]
        tick = 0

        while not self._sim_stop.is_set():
            now_epoch = time.time()
            ts_str = datetime.fromtimestamp(now_epoch).strftime("%H:%M:%S.%f")[:-3]
            tick += 1

            choice = random.random()
            if choice < 0.62:
                proto = "TCP"
                src_ip = random.choice(normal_hosts)
                dst_ip = random.choice(external_servers)
                src_port = random.randint(49152, 65500)
                dst_port = random.choice([443, 80, 22, 8080])
                flags = random.choice(["A", "PA", "SA"])
                size = random.randint(64, 1460)
                dns_q = None
            elif choice < 0.85:
                proto = "UDP"
                src_ip = random.choice(normal_hosts)
                dst_ip = random.choice(external_servers)
                src_port = random.randint(49152, 65500)
                dst_port = random.choice([443, 123, 5353])
                flags = None
                size = random.randint(60, 900)
                dns_q = None
            elif choice < 0.96:
                proto = "DNS"
                src_ip = random.choice(normal_hosts)
                dst_ip = "8.8.8.8"
                src_port = random.randint(49152, 65500)
                dst_port = 53
                flags = None
                size = random.randint(68, 128)
                dns_q = random.choice(dns_domains)
            else:
                proto = "ICMP"
                src_ip = random.choice(normal_hosts)
                dst_ip = "192.168.1.1"
                src_port = None
                dst_port = None
                flags = None
                size = 74
                dns_q = None

            self._enqueue_meta(
                {
                    "epoch": now_epoch,
                    "timestamp": ts_str,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": proto,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "size": size,
                    "tcp_flags": flags,
                    "dns_query": dns_q,
                    "status": "Normal",
                    "threat": None,
                }
            )

            # Periodically simulate realistic security events so live IDS detection can be demonstrated
            if tick % 45 == 0:
                scanner_ip = random.choice(["185.220.101.4", "45.33.32.156", "192.168.1.99"])
                for p in random.sample(range(20, 1024), 16):
                    t_now = time.time()
                    self._enqueue_meta(
                        {
                            "epoch": t_now,
                            "timestamp": datetime.fromtimestamp(t_now).strftime("%H:%M:%S.%f")[:-3],
                            "src_ip": scanner_ip,
                            "dst_ip": "192.168.1.10",
                            "protocol": "TCP",
                            "src_port": random.randint(40000, 60000),
                            "dst_port": p,
                            "size": 60,
                            "tcp_flags": "S",
                            "dns_query": None,
                            "status": "Normal",
                            "threat": None,
                        }
                    )
            elif tick % 75 == 0:
                attacker_ip = random.choice(["103.45.67.89", "91.240.118.172"])
                for _ in range(36):
                    t_now = time.time()
                    self._enqueue_meta(
                        {
                            "epoch": t_now,
                            "timestamp": datetime.fromtimestamp(t_now).strftime("%H:%M:%S.%f")[:-3],
                            "src_ip": attacker_ip,
                            "dst_ip": "192.168.1.10",
                            "protocol": "TCP",
                            "src_port": random.randint(1024, 65535),
                            "dst_port": 443,
                            "size": 60,
                            "tcp_flags": "S",
                            "dns_query": None,
                            "status": "Normal",
                            "threat": None,
                        }
                    )

            time.sleep(random.uniform(0.08, 0.22))

    def start(self, interface_label: str, interface_device: str) -> Tuple[bool, str]:
        with self._lock:
            if self.status == "Running":
                return True, "Packet monitoring is already running."

            if not interface_device:
                self.status = "Error"
                self.error_message = "No valid network interface selected."
                return False, self.error_message

            self.status = "Starting"
            self.error_message = ""
            self.selected_interface_label = interface_label
            self.selected_interface_device = interface_device

            if interface_device == SIMULATOR_DEVICE:
                self._sim_stop.clear()
                self._sim_thread = threading.Thread(
                    target=self._run_simulator_loop, name="NetShield-Simulator", daemon=True
                )
                self._sim_thread.start()
                self.status = "Running"
                self.mode = "Cloud Demo Simulator"
                return True, "Cloud Demo Simulator started (generating live traffic & threat patterns)."

            if not SCAPY_AVAILABLE:
                self.status = "Error"
                self.error_message = f"Scapy unavailable: {SCAPY_IMPORT_ERROR}"
                return False, self.error_message

            try:
                bpf = "(ip or ip6) and not port 8501"
                try:
                    sniffer = AsyncSniffer(
                        iface=interface_device,
                        prn=self._on_packet,
                        store=False,
                        filter=bpf,
                    )
                    sniffer.start()
                except Exception:
                    sniffer = AsyncSniffer(
                        iface=interface_device,
                        prn=self._on_packet,
                        store=False,
                    )
                    sniffer.start()

                time.sleep(0.15)
                if not getattr(sniffer, "running", True):
                    raise RuntimeError(
                        "Sniffer stopped immediately. Verify Npcap is installed and run terminal as Administrator."
                    )

                self.sniffer = sniffer
                self.status = "Running"
                self.mode = "Live Hardware Capture"
                return True, f"Live capture started on {interface_label}"

            except PermissionError:
                self.sniffer = None
                self.status = "Error"
                self.error_message = (
                    "Permission denied for raw packet capture. On local Windows, run terminal as Administrator. "
                    "On Streamlit Community Cloud, select 'Cloud Demo / Live Traffic Simulator' from the interface dropdown."
                )
                return False, self.error_message
            except Exception as exc:
                self.sniffer = None
                self.status = "Error"
                msg = str(exc)
                if "winpcap" in msg.lower() or "npcap" in msg.lower() or "layer 2" in msg.lower():
                    self.error_message = (
                        f"Npcap driver required on Windows ({msg}). Install Npcap with WinPcap API-compatible Mode enabled."
                    )
                else:
                    self.error_message = (
                        f"Capture failed ({msg}). If running on Streamlit Cloud, choose 'Cloud Demo / Live Traffic Simulator'."
                    )
                return False, self.error_message

    def stop(self) -> None:
        with self._lock:
            self._sim_stop.set()
            if self.sniffer is not None:
                try:
                    self.sniffer.stop()
                except Exception:
                    pass
                self.sniffer = None
            self.mode = "Stopped"
            if self.status != "Error":
                self.status = "Stopped"
