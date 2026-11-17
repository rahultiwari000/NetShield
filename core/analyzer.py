import threading
import time
from collections import Counter, deque
from typing import Any, Dict


class TrafficAnalyzer:
    def __init__(self, max_packets: int = 1000):
        self._lock = threading.Lock()
        self.recent_packets: deque = deque(maxlen=max_packets)
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.protocol_counts: Counter = Counter()
        self.src_ip_counts: Counter = Counter()
        self.dst_ip_counts: Counter = Counter()
        self.dst_port_counts: Counter = Counter()
        self.packet_timestamps: deque = deque(maxlen=10000)
        self.second_buckets: Dict[int, Dict[str, int]] = {}

    def record_packet(self, pkt: Dict[str, Any]) -> None:
        with self._lock:
            self.recent_packets.appendleft(pkt)
            self.total_packets += 1
            self.total_bytes += pkt["size"]
            self.protocol_counts[pkt["protocol"]] += 1
            self.src_ip_counts[pkt["src_ip"]] += 1
            self.dst_ip_counts[pkt["dst_ip"]] += 1
            if pkt["dst_port"] is not None:
                self.dst_port_counts[pkt["dst_port"]] += 1

            now_epoch = pkt["epoch"]
            self.packet_timestamps.append(now_epoch)

            sec_key = int(now_epoch)
            bucket = self.second_buckets.get(sec_key)
            if bucket is None:
                bucket = {"packets": 0, "bytes": 0}
                self.second_buckets[sec_key] = bucket
            bucket["packets"] += 1
            bucket["bytes"] += pkt["size"]

            if len(self.second_buckets) > 1800:
                cutoff = sec_key - 1800
                stale_keys = [k for k in self.second_buckets if k < cutoff]
                for k in stale_keys:
                    del self.second_buckets[k]

    def get_current_pps(self, window: float = 3.0) -> float:
        now = time.time()
        cutoff = now - window
        with self._lock:
            while self.packet_timestamps and self.packet_timestamps[0] < cutoff:
                self.packet_timestamps.popleft()
            count = len(self.packet_timestamps)
        return round(count / window, 1)

    def get_snapshot(self) -> Dict[str, Any]:
        pps = self.get_current_pps(3.0)
        with self._lock:
            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "pps": pps,
                "unique_src_ips": len(self.src_ip_counts),
                "protocol_counts": dict(self.protocol_counts),
                "top_src_ips": self.src_ip_counts.most_common(10),
                "top_dst_ports": self.dst_port_counts.most_common(10),
                "recent_packets": list(self.recent_packets),
                "second_buckets": dict(self.second_buckets),
            }

    def reset(self) -> None:
        with self._lock:
            self.recent_packets.clear()
            self.total_packets = 0
            self.total_bytes = 0
            self.protocol_counts.clear()
            self.src_ip_counts.clear()
            self.dst_ip_counts.clear()
            self.dst_port_counts.clear()
            self.packet_timestamps.clear()
            self.second_buckets.clear()
