import sqlite3
import threading
from datetime import datetime
from typing import Any, List, Optional

import pandas as pd


class Database:
    def __init__(self, db_path: str = "netshield.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self.init_db()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        con.execute("PRAGMA journal_mode=WAL;")
        return con

    def init_db(self) -> None:
        with self._lock:
            con = self._connect()
            try:
                cur = con.cursor()
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        src_ip TEXT NOT NULL,
                        dst_ip TEXT DEFAULT 'N/A',
                        threat TEXT NOT NULL,
                        protocol TEXT DEFAULT 'N/A',
                        severity TEXT NOT NULL,
                        details TEXT
                    )
                    """
                )
                cur.execute("PRAGMA table_info(alerts)")
                existing_cols = {row[1] for row in cur.fetchall()}
                if "dst_ip" not in existing_cols:
                    cur.execute("ALTER TABLE alerts ADD COLUMN dst_ip TEXT DEFAULT 'N/A'")
                if "protocol" not in existing_cols:
                    cur.execute("ALTER TABLE alerts ADD COLUMN protocol TEXT DEFAULT 'N/A'")
                con.commit()
            finally:
                con.close()

    def add_alert(
        self,
        src_ip: str,
        dst_ip: str,
        threat: str,
        protocol: str,
        severity: str,
        details: str,
        timestamp: Optional[str] = None,
    ) -> None:
        ts = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            con = self._connect()
            try:
                con.execute(
                    """
                    INSERT INTO alerts (timestamp, src_ip, dst_ip, threat, protocol, severity, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (ts, src_ip, dst_ip or "N/A", threat, protocol or "N/A", severity, details),
                )
                con.commit()
            finally:
                con.close()

    def fetch_alerts_df(
        self,
        search_ip: str = "",
        severity: str = "All",
        threat_type: str = "All",
        date_filter: str = "",
        sort_order: str = "Newest First",
        limit: int = 1000,
    ) -> pd.DataFrame:
        columns = ["id", "timestamp", "src_ip", "dst_ip", "threat", "protocol", "severity", "details"]
        query = f"SELECT {', '.join(columns)} FROM alerts WHERE 1=1"
        params: List[Any] = []

        if search_ip.strip():
            query += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR details LIKE ?)"
            like_term = f"%{search_ip.strip()}%"
            params.extend([like_term, like_term, like_term])

        if severity != "All":
            query += " AND severity = ?"
            params.append(severity)

        if threat_type != "All":
            query += " AND threat = ?"
            params.append(threat_type)

        if date_filter.strip():
            query += " AND timestamp LIKE ?"
            params.append(f"{date_filter.strip()}%")

        order_clause = "ORDER BY id DESC" if sort_order == "Newest First" else "ORDER BY id ASC"
        query += f" {order_clause} LIMIT ?"
        params.append(limit)

        with self._lock:
            con = self._connect()
            try:
                cur = con.cursor()
                cur.execute(query, params)
                rows = cur.fetchall()
            finally:
                con.close()

        return pd.DataFrame(rows, columns=columns)

    def clear_alerts(self) -> None:
        with self._lock:
            con = self._connect()
            try:
                con.execute("DELETE FROM alerts")
                con.commit()
            finally:
                con.close()
