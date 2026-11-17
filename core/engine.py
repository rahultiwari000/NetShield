import queue
import threading
from typing import Any, Dict

from core.analyzer import TrafficAnalyzer
from core.capture import PacketCapture
from core.database import Database
from core.detector import DetectionConfig, IntrusionDetector


class MonitorEngine:
    def __init__(self, db_path: str = "netshield.db"):
        self.db = Database(db_path)
        self.config = DetectionConfig()
        self.detector = IntrusionDetector(self.config)
        self.analyzer = TrafficAnalyzer(max_packets=1000)
        self.packet_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=2500)
        self.capture = PacketCapture(self.packet_queue)
        self._stop_event = threading.Event()
        self._consumer_thread = threading.Thread(
            target=self._consume_loop, name="NetShield-Consumer", daemon=True
        )
        self._consumer_thread.start()

    def _consume_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                pkt = self.packet_queue.get(timeout=0.25)
            except queue.Empty:
                continue

            try:
                alerts = self.detector.analyze(pkt)
                self.analyzer.record_packet(pkt)
                for alert in alerts:
                    self.db.add_alert(
                        src_ip=alert["src_ip"],
                        dst_ip=alert["dst_ip"],
                        threat=alert["threat"],
                        protocol=alert["protocol"],
                        severity=alert["severity"],
                        details=alert["details"],
                        timestamp=alert["timestamp"],
                    )
            except Exception:
                pass
