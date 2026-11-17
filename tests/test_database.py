import os
import unittest

from core.database import Database


class TestDatabase(unittest.TestCase):
    def setUp(self) -> None:
        self.test_db = "test_netshield_unit.db"
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        self.db = Database(self.test_db)

    def tearDown(self) -> None:
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def test_insert_and_filter_alerts(self) -> None:
        self.db.add_alert(
            src_ip="192.168.1.25",
            dst_ip="192.168.1.1",
            threat="Port Scan",
            protocol="TCP",
            severity="Medium",
            details="Probed 15 distinct ports",
            timestamp="2026-11-17 10:00:00",
        )
        self.db.add_alert(
            src_ip="10.0.0.99",
            dst_ip="192.168.1.1",
            threat="TCP SYN Flood",
            protocol="TCP",
            severity="Critical",
            details="High SYN burst",
            timestamp="2026-11-17 10:05:00",
        )

        all_df = self.db.fetch_alerts_df()
        self.assertEqual(len(all_df), 2)

        crit_df = self.db.fetch_alerts_df(severity="Critical")
        self.assertEqual(len(crit_df), 1)
        self.assertEqual(crit_df.iloc[0]["src_ip"], "10.0.0.99")

        scan_df = self.db.fetch_alerts_df(threat_type="Port Scan")
        self.assertEqual(len(scan_df), 1)
        self.assertEqual(scan_df.iloc[0]["src_ip"], "192.168.1.25")

    def test_clear_alerts(self) -> None:
        self.db.add_alert("1.2.3.4", "5.6.7.8", "ICMP Flood", "ICMP", "Medium", "ICMP spike")
        self.assertEqual(len(self.db.fetch_alerts_df()), 1)
        self.db.clear_alerts()
        self.assertEqual(len(self.db.fetch_alerts_df()), 0)


if __name__ == "__main__":
    unittest.main()
