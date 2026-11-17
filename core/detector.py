import threading
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class DetectionConfig:
    window_sec: int = 10
    flood_threshold: int = 50
    port_scan_threshold: int = 12
    syn_flood_threshold: int = 30
    icmp_flood_threshold: int = 20
    cooldown_sec: int = 15


class IntrusionDetector:
    def __init__(self, config: Optional[DetectionConfig] = None):
        self.config = config or DetectionConfig()
        self._lock = threading.Lock()
        self.all_packets_window: Dict[str, deque] = defaultdict(deque)
        self.port_scan_window: Dict[str, deque] = defaultdict(deque)
        self.syn_window: Dict[str, deque] = defaultdict(deque)
        self.icmp_window: Dict[str, deque] = defaultdict(deque)
        self.last_alert_ts: Dict[Tuple[str, str], float] = {}
        self.session_alerts: deque = deque(maxlen=500)
        self.total_threats_detected: int = 0

    def update_config(self, config: DetectionConfig) -> None:
        with self._lock:
            self.config = config

    @staticmethod
    def _prune_timestamps(dq: deque, cutoff: float) -> None:
        while dq and dq[0] < cutoff:
            dq.popleft()

    @staticmethod
    def _prune_port_pairs(dq: deque, cutoff: float) -> None:
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def analyze(self, pkt: Dict[str, Any]) -> List[Dict[str, Any]]:
        now = pkt["epoch"]
        src_ip = pkt["src_ip"]
        dst_ip = pkt["dst_ip"]
        protocol = pkt["protocol"]
        dst_port = pkt["dst_port"]
        tcp_flags = pkt["tcp_flags"] or ""

        triggered_findings: List[Tuple[str, str, str]] = []

        with self._lock:
            cfg = self.config
            cutoff = now - cfg.window_sec

            pkt_dq = self.all_packets_window[src_ip]
            pkt_dq.append(now)
            self._prune_timestamps(pkt_dq, cutoff)
            pkt_count = len(pkt_dq)
            if pkt_count > cfg.flood_threshold:
                sev = "Critical" if pkt_count > cfg.flood_threshold * 3 else "High"
                triggered_findings.append(
                    (
                        "DDoS / Packet Flood",
                        sev,
                        f"Suspected flood: {src_ip} sent {pkt_count} packets in {cfg.window_sec}s (threshold: {cfg.flood_threshold}).",
                    )
                )

            if dst_port is not None:
                ps_dq = self.port_scan_window[src_ip]
                ps_dq.append((now, dst_port))
                self._prune_port_pairs(ps_dq, cutoff)
                distinct_ports = {p for _, p in ps_dq}
                if len(distinct_ports) > cfg.port_scan_threshold:
                    sev = "High" if len(distinct_ports) > cfg.port_scan_threshold * 2 else "Medium"
                    sample_ports = sorted(distinct_ports)[:8]
                    triggered_findings.append(
                        (
                            "Port Scan",
                            sev,
                            f"Suspected port scan: {src_ip} contacted {len(distinct_ports)} distinct ports in {cfg.window_sec}s (sample: {sample_ports}).",
                        )
                    )

            if protocol == "TCP" and ("S" in tcp_flags and "A" not in tcp_flags):
                syn_dq = self.syn_window[src_ip]
                syn_dq.append(now)
                self._prune_timestamps(syn_dq, cutoff)
                syn_count = len(syn_dq)
                if syn_count > cfg.syn_flood_threshold:
                    sev = "Critical" if syn_count > cfg.syn_flood_threshold * 3 else "High"
                    triggered_findings.append(
                        (
                            "TCP SYN Flood",
                            sev,
                            f"Abnormal TCP SYN burst: {src_ip} sent {syn_count} SYN packets toward {dst_ip} in {cfg.window_sec}s (threshold: {cfg.syn_flood_threshold}).",
                        )
                    )

            if protocol == "ICMP":
                icmp_dq = self.icmp_window[src_ip]
                icmp_dq.append(now)
                self._prune_timestamps(icmp_dq, cutoff)
                icmp_count = len(icmp_dq)
                if icmp_count > cfg.icmp_flood_threshold:
                    sev = "High" if icmp_count > cfg.icmp_flood_threshold * 3 else "Medium"
                    triggered_findings.append(
                        (
                            "ICMP Flood",
                            sev,
                            f"Abnormal ICMP burst: {src_ip} sent {icmp_count} ICMP packets in {cfg.window_sec}s (threshold: {cfg.icmp_flood_threshold}).",
                        )
                    )

            severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            if triggered_findings:
                top_finding = max(triggered_findings, key=lambda x: severity_rank.get(x[1], 0))
                pkt["status"] = top_finding[1]
                pkt["threat"] = top_finding[0]

            emitted_alerts: List[Dict[str, Any]] = []
            for threat_name, severity, details in triggered_findings:
                key = (src_ip, threat_name)
                last_ts = self.last_alert_ts.get(key, 0.0)
                if now - last_ts >= cfg.cooldown_sec:
                    self.last_alert_ts[key] = now
                    self.total_threats_detected += 1
                    alert_record = {
                        "timestamp": datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S"),
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "threat": threat_name,
                        "protocol": protocol,
                        "severity": severity,
                        "details": details,
                    }
                    self.session_alerts.appendleft(alert_record)
                    emitted_alerts.append(alert_record)

            return emitted_alerts

    def get_session_alerts(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.session_alerts)

    def reset(self) -> None:
        with self._lock:
            self.all_packets_window.clear()
            self.port_scan_window.clear()
            self.syn_window.clear()
            self.icmp_window.clear()
            self.last_alert_ts.clear()
            self.session_alerts.clear()
            self.total_threats_detected = 0
