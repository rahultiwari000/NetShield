import time
import unittest

from core.detector import DetectionConfig, IntrusionDetector


class TestIntrusionDetector(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = IntrusionDetector(
            DetectionConfig(
                window_sec=10,
                flood_threshold=20,
                port_scan_threshold=5,
                syn_flood_threshold=10,
                icmp_flood_threshold=8,
                cooldown_sec=15,
            )
        )

    def _make_pkt(
        self,
        epoch: float,
        src_ip: str = "192.168.1.50",
        dst_ip: str = "192.168.1.1",
        protocol: str = "TCP",
        dst_port: int = 80,
        tcp_flags: str = "A",
    ) -> dict:
        return {
            "epoch": epoch,
            "timestamp": "12:00:00.000",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "src_port": 50000,
            "dst_port": dst_port,
            "size": 64,
            "tcp_flags": tcp_flags,
            "dns_query": None,
            "status": "Normal",
            "threat": None,
        }

    def test_port_scan_and_cooldown(self) -> None:
        now = time.time()
        alerts = []
        for idx, port in enumerate(range(2000, 2010)):
            alerts.extend(self.detector.analyze(self._make_pkt(now + idx * 0.05, dst_port=port)))

        scan_alerts = [a for a in alerts if a["threat"] == "Port Scan"]
        self.assertEqual(len(scan_alerts), 1)

    def test_syn_flood_detection(self) -> None:
        now = time.time()
        alerts = []
        for idx in range(15):
            alerts.extend(self.detector.analyze(self._make_pkt(now + idx * 0.05, tcp_flags="S")))

        syn_alerts = [a for a in alerts if a["threat"] == "TCP SYN Flood"]
        self.assertEqual(len(syn_alerts), 1)

    def test_icmp_flood_detection(self) -> None:
        now = time.time()
        alerts = []
        for idx in range(12):
            alerts.extend(
                self.detector.analyze(
                    self._make_pkt(now + idx * 0.05, protocol="ICMP", dst_port=None, tcp_flags="")
                )
            )

        icmp_alerts = [a for a in alerts if a["threat"] == "ICMP Flood"]
        self.assertEqual(len(icmp_alerts), 1)

    def test_ddos_packet_flood_detection(self) -> None:
        now = time.time()
        alerts = []
        for idx in range(25):
            alerts.extend(self.detector.analyze(self._make_pkt(now + idx * 0.05, protocol="UDP", tcp_flags="")))

        flood_alerts = [a for a in alerts if a["threat"] == "DDoS / Packet Flood"]
        self.assertEqual(len(flood_alerts), 1)


if __name__ == "__main__":
    unittest.main()
