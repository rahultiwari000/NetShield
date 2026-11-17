import time
from datetime import datetime
from typing import Any, Dict

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from core.capture import SIMULATOR_DEVICE, SIMULATOR_LABEL, PacketCapture, is_cloud_environment
from core.detector import DetectionConfig
from core.engine import MonitorEngine

DB_PATH = "netshield.db"

COMMON_PORTS: Dict[int, str] = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
}


@st.cache_resource
def get_monitor_engine() -> MonitorEngine:
    return MonitorEngine(DB_PATH)


def inject_dark_theme_css() -> None:
    st.markdown(
        """
        <style>
        .stApp {
            background-color: #0B1120;
            color: #E2E8F0;
        }
        header[data-testid="stHeader"] {
            background-color: rgba(11, 17, 32, 0.9);
        }
        div[data-testid="stMetric"] {
            background-color: #131C31;
            border: 1px solid #1E293B;
            border-radius: 10px;
            padding: 14px 16px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
        }
        div[data-testid="stMetricLabel"] {
            color: #94A3B8 !important;
            font-size: 0.85rem !important;
        }
        div[data-testid="stMetricValue"] {
            color: #F8FAFC !important;
            font-size: 1.55rem !important;
        }
        div[data-testid="stRadio"] > div {
            background-color: #131C31;
            border: 1px solid #1E293B;
            border-radius: 10px;
            padding: 6px 10px;
            gap: 8px;
        }
        div[data-testid="stRadio"] label {
            background-color: #1E293B;
            border-radius: 8px;
            padding: 6px 16px;
            color: #CBD5E1 !important;
            border: 1px solid transparent;
            transition: all 0.15s ease;
        }
        div[data-testid="stRadio"] label:has(input:checked) {
            background-color: #0F2942;
            border: 1px solid #38BDF8;
            color: #38BDF8 !important;
            font-weight: 600;
        }
        .status-badge {
            display: inline-block;
            padding: 6px 14px;
            border-radius: 999px;
            font-weight: 600;
            font-size: 0.85rem;
            letter-spacing: 0.02em;
        }
        .status-running {
            background-color: rgba(16, 185, 129, 0.16);
            color: #10B981;
            border: 1px solid rgba(16, 185, 129, 0.45);
        }
        .status-stopped {
            background-color: rgba(148, 163, 184, 0.16);
            color: #94A3B8;
            border: 1px solid rgba(148, 163, 184, 0.35);
        }
        .status-error {
            background-color: rgba(239, 68, 68, 0.16);
            color: #EF4444;
            border: 1px solid rgba(239, 68, 68, 0.45);
        }
        .section-card {
            background-color: #131C31;
            border: 1px solid #1E293B;
            border-radius: 10px;
            padding: 16px;
            margin-bottom: 12px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def format_bytes(num_bytes: int) -> str:
    value = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if value < 1024.0:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} TB"


def style_severity_df(df: pd.DataFrame, col_name: str = "severity"):
    if df.empty or col_name not in df.columns:
        return df

    def color_sev(val: str) -> str:
        mapping = {
            "Critical": "background-color: rgba(239, 68, 68, 0.25); color: #FCA5A5; font-weight: 700;",
            "High": "background-color: rgba(249, 115, 22, 0.22); color: #FDBA74; font-weight: 600;",
            "Medium": "background-color: rgba(245, 158, 11, 0.20); color: #FCD34D; font-weight: 600;",
            "Low": "background-color: rgba(59, 130, 246, 0.20); color: #93C5FD;",
            "Normal": "color: #10B981;",
        }
        return mapping.get(str(val), "")

    return df.style.map(color_sev, subset=[col_name])


def render_monitoring_control_bar(engine: MonitorEngine) -> None:
    interfaces = PacketCapture.list_interfaces()
    iface_map = {label: dev for label, dev in interfaces}
    iface_labels = list(iface_map.keys())

    c_iface, c_start, c_stop, c_status, c_refresh, c_cfg = st.columns([3.3, 1.2, 1.2, 1.5, 1.3, 1.5])

    with c_iface:
        default_idx = 0
        if engine.capture.selected_interface_label in iface_labels:
            default_idx = iface_labels.index(engine.capture.selected_interface_label)
        selected_label = st.selectbox(
            "Network Interface",
            options=iface_labels,
            index=default_idx,
            label_visibility="collapsed",
            key="selected_iface_widget",
        )

    with c_start:
        if st.button("Start Monitoring", use_container_width=True, type="primary"):
            ok, msg = engine.capture.start(selected_label, iface_map[selected_label])
            if ok:
                st.toast(msg)
            else:
                st.error(msg)

    with c_stop:
        if st.button("Stop Monitoring", use_container_width=True):
            engine.capture.stop()
            st.toast("Packet monitoring stopped.")

    with c_status:
        status = engine.capture.status
        if status == "Running":
            badge_text = "CLOUD DEMO" if engine.capture.mode == "Cloud Demo Simulator" else "RUNNING"
            st.markdown(f'<span class="status-badge status-running">{badge_text}</span>', unsafe_allow_html=True)
        elif status == "Error":
            st.markdown('<span class="status-badge status-error">ERROR</span>', unsafe_allow_html=True)
        else:
            st.markdown(f'<span class="status-badge status-stopped">{status.upper()}</span>', unsafe_allow_html=True)

    with c_refresh:
        st.session_state.auto_refresh = st.toggle(
            "Auto-Refresh",
            value=st.session_state.get("auto_refresh", True),
            key="auto_refresh_toggle",
        )

    with c_cfg:
        with st.popover("Rule Thresholds", use_container_width=True):
            st.markdown("**Detection Sensitivity (Rolling Window)**")
            cfg = engine.detector.config
            w_sec = st.number_input("Window (seconds)", min_value=2, max_value=120, value=cfg.window_sec)
            flood_th = st.number_input("DDoS / Packet Flood (pkts)", min_value=5, max_value=5000, value=cfg.flood_threshold)
            scan_th = st.number_input("Port Scan (unique ports)", min_value=3, max_value=500, value=cfg.port_scan_threshold)
            syn_th = st.number_input("TCP SYN Flood (SYN pkts)", min_value=5, max_value=5000, value=cfg.syn_flood_threshold)
            icmp_th = st.number_input("ICMP Flood (ICMP pkts)", min_value=5, max_value=5000, value=cfg.icmp_flood_threshold)
            cd_sec = st.number_input("Alert Cooldown (seconds)", min_value=1, max_value=300, value=cfg.cooldown_sec)

            b_apply, b_reset = st.columns(2)
            with b_apply:
                if st.button("Apply", use_container_width=True, type="primary"):
                    engine.detector.update_config(
                        DetectionConfig(
                            window_sec=int(w_sec),
                            flood_threshold=int(flood_th),
                            port_scan_threshold=int(scan_th),
                            syn_flood_threshold=int(syn_th),
                            icmp_flood_threshold=int(icmp_th),
                            cooldown_sec=int(cd_sec),
                        )
                    )
                    st.toast("Detection thresholds updated.")
            with b_reset:
                if st.button("Reset Stats", use_container_width=True):
                    engine.analyzer.reset()
                    engine.detector.reset()
                    st.toast("Session counters cleared.")

    if engine.capture.status == "Error" and engine.capture.error_message:
        st.error(engine.capture.error_message)


def build_time_series_df(second_buckets: Dict[int, Dict[str, int]], range_label: str) -> pd.DataFrame:
    if not second_buckets:
        return pd.DataFrame(columns=["Time", "Packets", "Bytes"])

    now_sec = int(time.time())
    range_map = {"Last 1 min": 60, "Last 5 min": 300, "Last 15 min": 900, "All Session": 86400}
    lookback = range_map.get(range_label, 300)
    cutoff = now_sec - lookback

    filtered = sorted((k, v) for k, v in second_buckets.items() if k >= cutoff)
    if not filtered:
        return pd.DataFrame(columns=["Time", "Packets", "Bytes"])

    rows = [
        {
            "Time": datetime.fromtimestamp(sec).strftime("%H:%M:%S"),
            "Packets": vals["packets"],
            "Bytes": vals["bytes"],
        }
        for sec, vals in filtered
    ]
    return pd.DataFrame(rows)


def render_overview_page(engine: MonitorEngine, snap: Dict[str, Any]) -> None:
    proto_counts = snap["protocol_counts"]
    session_alerts = engine.detector.get_session_alerts()

    r1 = st.columns(4)
    r1[0].metric("Total Packets Captured", f"{snap['total_packets']:,}", format_bytes(snap["total_bytes"]))
    r1[1].metric("Packets Per Second", f"{snap['pps']:.1f} pkt/s")
    r1[2].metric("Detected Threats (Session)", f"{engine.detector.total_threats_detected:,}")
    r1[3].metric("Unique Source IPs", f"{snap['unique_src_ips']:,}")

    r2 = st.columns(4)
    r2[0].metric("TCP Packets", f"{proto_counts.get('TCP', 0):,}")
    r2[1].metric("UDP Packets", f"{proto_counts.get('UDP', 0):,}")
    r2[2].metric("ICMP Packets", f"{proto_counts.get('ICMP', 0):,}")
    r2[3].metric("Capture Mode", engine.capture.mode)

    st.markdown("---")
    left_col, right_col = st.columns([1.45, 1.0])

    with left_col:
        h_col, t_col = st.columns([2, 1])
        with h_col:
            st.subheader("Live Packet Rate")
        with t_col:
            ov_range = st.selectbox(
                "Window",
                ["Last 1 min", "Last 5 min", "Last 15 min", "All Session"],
                index=1,
                key="overview_time_range",
                label_visibility="collapsed",
            )

        ts_df = build_time_series_df(snap["second_buckets"], ov_range)
        if ts_df.empty:
            st.info("Select a network interface (or Cloud Demo Simulator) and click Start Monitoring.")
        else:
            fig = px.area(ts_df, x="Time", y="Packets", markers=True, color_discrete_sequence=["#38BDF8"])
            fig.update_layout(
                height=300,
                margin=dict(l=10, r=10, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#E2E8F0"),
                xaxis=dict(showgrid=False),
                yaxis=dict(gridcolor="#1E293B", title="Packets / sec"),
            )
            st.plotly_chart(fig, use_container_width=True)

    with right_col:
        st.subheader("Recent Security Alerts")
        if session_alerts:
            recent_df = pd.DataFrame(session_alerts[:5])[["timestamp", "src_ip", "threat", "severity"]]
            st.dataframe(style_severity_df(recent_df), use_container_width=True, hide_index=True, height=300)
        else:
            persisted_recent = engine.db.fetch_alerts_df(limit=5)
            if persisted_recent.empty:
                st.info("No suspicious activity detected yet.")
            else:
                st.dataframe(
                    style_severity_df(persisted_recent[["timestamp", "src_ip", "threat", "severity"]]),
                    use_container_width=True,
                    hide_index=True,
                    height=300,
                )


def render_live_traffic_page(snap: Dict[str, Any]) -> None:
    st.subheader("Live Network Traffic Stream")

    c1, c2, c3, c4, c5, c6 = st.columns([1.2, 1.4, 1.4, 1.1, 1.1, 1.2])
    with c1:
        paused = st.session_state.get("pause_live_table", False)
        btn_label = "Resume Display" if paused else "Pause Display"
        if st.button(btn_label, use_container_width=True):
            paused = not paused
            st.session_state.pause_live_table = paused
            if paused:
                st.session_state.paused_snapshot = list(snap["recent_packets"])

    with c2:
        src_search = st.text_input("Search Source IP", placeholder="e.g. 192.168.1.", key="lt_src")
    with c3:
        dst_search = st.text_input("Search Destination IP", placeholder="e.g. 8.8.8.8", key="lt_dst")
    with c4:
        proto_filter = st.selectbox("Protocol", ["All", "TCP", "UDP", "ICMP", "DNS", "OTHER"], key="lt_proto")
    with c5:
        status_filter = st.selectbox("Status", ["All", "Normal", "Suspicious"], key="lt_status")
    with c6:
        sort_by = st.selectbox("Sort By", ["Newest", "Oldest", "Largest Packet"], key="lt_sort")

    if st.session_state.get("pause_live_table", False):
        st.warning("Live display is paused for inspection. Background packet capture remains active.")
        packets = st.session_state.get("paused_snapshot", [])
    else:
        packets = snap["recent_packets"]

    if not packets:
        st.info("No captured packets in buffer yet. Start monitoring to view live packets.")
        return

    df = pd.DataFrame(packets)

    if src_search.strip():
        df = df[df["src_ip"].str.contains(src_search.strip(), case=False, na=False)]
    if dst_search.strip():
        df = df[df["dst_ip"].str.contains(dst_search.strip(), case=False, na=False)]
    if proto_filter != "All":
        df = df[df["protocol"] == proto_filter]
    if status_filter == "Normal":
        df = df[df["status"] == "Normal"]
    elif status_filter == "Suspicious":
        df = df[df["status"] != "Normal"]

    if sort_by == "Oldest":
        df = df.iloc[::-1]
    elif sort_by == "Largest Packet":
        df = df.sort_values(by="size", ascending=False)

    display_df = df.head(250).copy()
    display_df["src_port"] = display_df["src_port"].fillna("-").astype(str).str.replace(r"\.0$", "", regex=True)
    display_df["dst_port"] = display_df["dst_port"].fillna("-").astype(str).str.replace(r"\.0$", "", regex=True)

    table_cols = ["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "size", "status"]
    st.dataframe(
        style_severity_df(display_df[table_cols], col_name="status"),
        use_container_width=True,
        hide_index=True,
        height=380,
    )

    if not display_df.empty:
        st.markdown("#### Packet Metadata Inspector")
        options = [
            f"#{idx} | {row['timestamp']} | {row['src_ip']}:{row['src_port']} -> {row['dst_ip']}:{row['dst_port']} ({row['protocol']}, {row['size']} B)"
            for idx, row in display_df.head(50).iterrows()
        ]
        selected_pkt_label = st.selectbox("Select a packet to inspect full header metadata:", options, key="pkt_inspect")
        selected_idx = int(selected_pkt_label.split("|")[0].strip().lstrip("#"))
        pkt_row = display_df.loc[selected_idx]

        ic1, ic2, ic3, ic4 = st.columns(4)
        ic1.metric("Source", f"{pkt_row['src_ip']}:{pkt_row['src_port']}")
        ic2.metric("Destination", f"{pkt_row['dst_ip']}:{pkt_row['dst_port']}")
        ic3.metric("Protocol / Flags", f"{pkt_row['protocol']} ({pkt_row['tcp_flags'] or 'None'})")
        ic4.metric("Packet Size / Status", f"{pkt_row['size']} B - {pkt_row['status']}")
        if pd.notna(pkt_row.get("dns_query")) and pkt_row.get("dns_query"):
            st.info(f"**DNS Query Domain:** `{pkt_row['dns_query']}`")


def render_threat_detection_page(engine: MonitorEngine, snap: Dict[str, Any]) -> None:
    st.subheader("Real-Time Intrusion Detection & Threat Investigation")

    session_alerts = engine.detector.get_session_alerts()
    df = pd.DataFrame(session_alerts) if session_alerts else engine.db.fetch_alerts_df(limit=200)

    s1, s2, s3, s4 = st.columns(4)
    s1.metric("Critical", int((df["severity"] == "Critical").sum()) if not df.empty else 0)
    s2.metric("High", int((df["severity"] == "High").sum()) if not df.empty else 0)
    s3.metric("Medium", int((df["severity"] == "Medium").sum()) if not df.empty else 0)
    s4.metric("Low", int((df["severity"] == "Low").sum()) if not df.empty else 0)

    f1, f2, f3 = st.columns([1.5, 1.2, 1.5])
    with f1:
        attack_filter = st.selectbox(
            "Filter by Attack Type",
            ["All", "DDoS / Packet Flood", "Port Scan", "TCP SYN Flood", "ICMP Flood"],
            key="td_attack",
        )
    with f2:
        sev_filter = st.selectbox(
            "Filter by Severity",
            ["All", "Critical", "High", "Medium", "Low"],
            key="td_sev",
        )
    with f3:
        ip_filter = st.text_input("Search IP Address", placeholder="Filter source or target IP...", key="td_ip")

    if df.empty:
        st.info("No threats detected yet. Active detection rules are monitoring live traffic.")
        return

    if attack_filter != "All":
        df = df[df["threat"] == attack_filter]
    if sev_filter != "All":
        df = df[df["severity"] == sev_filter]
    if ip_filter.strip():
        q = ip_filter.strip()
        df = df[
            df["src_ip"].str.contains(q, case=False, na=False)
            | df["dst_ip"].str.contains(q, case=False, na=False)
        ]

    show_cols = ["timestamp", "src_ip", "dst_ip", "threat", "protocol", "severity", "details"]
    st.dataframe(style_severity_df(df[show_cols]), use_container_width=True, hide_index=True, height=320)

    if not df.empty:
        st.markdown("#### Alert Investigation & Related Source Traffic")
        alert_labels = [
            f"[{row['severity']}] {row['timestamp']} - {row['threat']} from {row['src_ip']}"
            for _, row in df.head(40).iterrows()
        ]
        chosen = st.selectbox("Select alert to investigate:", alert_labels, key="td_inspect")
        chosen_idx = alert_labels.index(chosen)
        alert_item = df.iloc[chosen_idx]

        st.markdown(
            f"""
            <div class="section-card">
                <strong>Attack Category:</strong> {alert_item['threat']} &nbsp;|&nbsp;
                <strong>Severity:</strong> {alert_item['severity']} &nbsp;|&nbsp;
                <strong>Protocol:</strong> {alert_item['protocol']}<br/>
                <strong>Source IP:</strong> <code>{alert_item['src_ip']}</code> &rarr;
                <strong>Destination IP:</strong> <code>{alert_item['dst_ip']}</code><br/>
                <strong>Detection Reason:</strong> {alert_item['details']}
            </div>
            """,
            unsafe_allow_html=True,
        )

        related_pkts = [p for p in snap["recent_packets"] if p["src_ip"] == alert_item["src_ip"]][:15]
        if related_pkts:
            st.caption(f"Recent captured packets from `{alert_item['src_ip']}`:")
            rel_df = pd.DataFrame(related_pkts)[
                ["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "tcp_flags", "size", "status"]
            ]
            st.dataframe(rel_df, use_container_width=True, hide_index=True)


def render_network_analytics_page(engine: MonitorEngine, snap: Dict[str, Any]) -> None:
    st.subheader("Interactive Network Traffic Analytics")

    if snap["total_packets"] == 0:
        st.info("No traffic captured yet. Start packet monitoring to generate interactive Plotly analytics.")
        return

    c1, c2 = st.columns([1.0, 1.4])

    with c1:
        st.markdown("**1. Protocol Distribution**")
        proto_dict = snap["protocol_counts"]
        proto_df = pd.DataFrame(
            [{"Protocol": k, "Packets": v} for k, v in proto_dict.items()]
        ).sort_values("Packets", ascending=False)
        fig_proto = px.pie(
            proto_df,
            names="Protocol",
            values="Packets",
            hole=0.45,
            color_discrete_sequence=["#38BDF8", "#10B981", "#F59E0B", "#A855F7", "#64748B"],
        )
        fig_proto.update_layout(
            height=300,
            margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#E2E8F0"),
        )
        st.plotly_chart(fig_proto, use_container_width=True)

        drill_proto = st.selectbox(
            "Inspect packets by protocol:",
            ["None"] + proto_df["Protocol"].tolist(),
            key="na_proto_drill",
        )
        if drill_proto != "None":
            matched = [p for p in snap["recent_packets"] if p["protocol"] == drill_proto][:10]
            if matched:
                st.dataframe(
                    pd.DataFrame(matched)[["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "size"]],
                    use_container_width=True,
                    hide_index=True,
                )

    with c2:
        t_head, t_sel = st.columns([2, 1])
        with t_head:
            st.markdown("**2. Traffic Volume Over Time**")
        with t_sel:
            na_range = st.selectbox(
                "Time Range",
                ["Last 1 min", "Last 5 min", "Last 15 min", "All Session"],
                index=1,
                key="na_time_range",
                label_visibility="collapsed",
            )
        ts_df = build_time_series_df(snap["second_buckets"], na_range)
        if not ts_df.empty:
            fig_time = go.Figure()
            fig_time.add_trace(
                go.Scatter(
                    x=ts_df["Time"],
                    y=ts_df["Packets"],
                    mode="lines+markers",
                    name="Packets/s",
                    line=dict(color="#10B981", width=2),
                )
            )
            fig_time.update_layout(
                height=300,
                margin=dict(l=10, r=10, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#E2E8F0"),
                xaxis=dict(showgrid=False),
                yaxis=dict(gridcolor="#1E293B", title="Packets"),
            )
            st.plotly_chart(fig_time, use_container_width=True)

    st.markdown("---")

    c3, c4 = st.columns(2)

    with c3:
        st.markdown("**3. Top Active Source IP Addresses**")
        top_ips = snap["top_src_ips"]
        if top_ips:
            ip_df = pd.DataFrame(top_ips, columns=["Source IP", "Packets"]).iloc[::-1]
            fig_ip = px.bar(
                ip_df,
                x="Packets",
                y="Source IP",
                orientation="h",
                color_discrete_sequence=["#38BDF8"],
            )
            fig_ip.update_layout(
                height=300,
                margin=dict(l=10, r=10, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#E2E8F0"),
                xaxis=dict(gridcolor="#1E293B"),
                yaxis=dict(showgrid=False),
            )
            st.plotly_chart(fig_ip, use_container_width=True)

            selected_ip = st.selectbox(
                "Explore traffic for Source IP:",
                ["None"] + [ip for ip, _ in top_ips],
                key="na_ip_drill",
            )
            if selected_ip != "None":
                ip_pkts = [p for p in snap["recent_packets"] if p["src_ip"] == selected_ip][:10]
                if ip_pkts:
                    st.dataframe(
                        pd.DataFrame(ip_pkts)[["timestamp", "dst_ip", "protocol", "dst_port", "size", "status"]],
                        use_container_width=True,
                        hide_index=True,
                    )

    with c4:
        st.markdown("**4. Destination Port Distribution**")
        top_ports = snap["top_dst_ports"]
        if top_ports:
            port_rows = [
                {
                    "Port": f"{p} ({COMMON_PORTS[p]})" if p in COMMON_PORTS else str(p),
                    "RawPort": p,
                    "Packets": cnt,
                }
                for p, cnt in top_ports
            ]
            port_df = pd.DataFrame(port_rows)
            fig_port = px.bar(
                port_df,
                x="Port",
                y="Packets",
                color_discrete_sequence=["#A855F7"],
            )
            fig_port.update_layout(
                height=300,
                margin=dict(l=10, r=10, t=10, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#E2E8F0"),
                xaxis=dict(showgrid=False),
                yaxis=dict(gridcolor="#1E293B"),
            )
            st.plotly_chart(fig_port, use_container_width=True)

            port_options = ["None"] + port_df["Port"].tolist()
            selected_port_label = st.selectbox("Explore traffic for Destination Port:", port_options, key="na_port_drill")
            if selected_port_label != "None":
                raw_p = int(selected_port_label.split(" ")[0])
                port_pkts = [p for p in snap["recent_packets"] if p["dst_port"] == raw_p][:10]
                if port_pkts:
                    st.dataframe(
                        pd.DataFrame(port_pkts)[["timestamp", "src_ip", "dst_ip", "protocol", "size", "status"]],
                        use_container_width=True,
                        hide_index=True,
                    )
        else:
            st.info("No TCP/UDP port traffic captured yet.")

    st.markdown("**5. Packet Rate & Flood Burst Timeline**")
    burst_df = build_time_series_df(snap["second_buckets"], na_range)
    if not burst_df.empty:
        per_sec_guide = max(1.0, engine.detector.config.flood_threshold / max(1, engine.detector.config.window_sec))
        fig_burst = go.Figure()
        fig_burst.add_trace(
            go.Scatter(
                x=burst_df["Time"],
                y=burst_df["Packets"],
                mode="lines",
                name="Observed PPS",
                line=dict(color="#F59E0B", width=2),
            )
        )
        fig_burst.add_hline(
            y=per_sec_guide,
            line_dash="dash",
            line_color="#EF4444",
            annotation_text=f"Sustained Flood Rate Guide ({per_sec_guide:.1f} pkt/s)",
        )
        fig_burst.update_layout(
            height=260,
            margin=dict(l=10, r=10, t=20, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#E2E8F0"),
            xaxis=dict(showgrid=False),
            yaxis=dict(gridcolor="#1E293B", title="Packets / sec"),
        )
        st.plotly_chart(fig_burst, use_container_width=True)


def render_alert_history_page(engine: MonitorEngine) -> None:
    st.subheader("Historical Security Alerts (SQLite Persistence)")

    f1, f2, f3, f4, f5 = st.columns([1.6, 1.1, 1.3, 1.1, 1.1])
    with f1:
        ah_search = st.text_input("Search IP or Details", placeholder="IP address or keyword...", key="ah_search")
    with f2:
        ah_sev = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low"], key="ah_sev")
    with f3:
        ah_cat = st.selectbox(
            "Attack Category",
            ["All", "DDoS / Packet Flood", "Port Scan", "TCP SYN Flood", "ICMP Flood"],
            key="ah_cat",
        )
    with f4:
        ah_date = st.text_input("Date (YYYY-MM-DD)", placeholder="e.g. 2026-11-17", key="ah_date")
    with f5:
        ah_sort = st.selectbox("Sort Order", ["Newest First", "Oldest First"], key="ah_sort")

    hist_df = engine.db.fetch_alerts_df(
        search_ip=ah_search,
        severity=ah_sev,
        threat_type=ah_cat,
        date_filter=ah_date,
        sort_order=ah_sort,
        limit=1000,
    )

    act1, act2, _ = st.columns([1.2, 1.6, 3.0])
    with act1:
        csv_bytes = hist_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "Export Filtered CSV",
            data=csv_bytes,
            file_name=f"netshield_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with act2:
        with st.popover("Clear Alert History", use_container_width=True):
            st.warning("This permanently deletes all saved alerts from `netshield.db`.")
            confirm_del = st.checkbox("I confirm I want to delete all alert records", key="confirm_clear_db")
            if st.button("Confirm Delete All", type="primary", disabled=not confirm_del, use_container_width=True):
                engine.db.clear_alerts()
                engine.detector.reset()
                st.toast("All historical alerts cleared from SQLite.")
                st.rerun()

    if hist_df.empty:
        st.info("No matching historical alerts stored in `netshield.db`.")
        return

    st.dataframe(style_severity_df(hist_df), use_container_width=True, hide_index=True, height=380)

    st.markdown("#### Stored Alert Inspector")
    record_labels = [
        f"ID #{row['id']} | {row['timestamp']} | [{row['severity']}] {row['threat']} ({row['src_ip']})"
        for _, row in hist_df.head(50).iterrows()
    ]
    chosen_rec = st.selectbox("Select alert record to inspect:", record_labels, key="ah_inspect")
    rec_id = int(chosen_rec.split("|")[0].replace("ID #", "").strip())
    rec_row = hist_df[hist_df["id"] == rec_id].iloc[0]

    st.markdown(
        f"""
        <div class="section-card">
            <strong>Alert ID:</strong> #{rec_row['id']} &nbsp;|&nbsp;
            <strong>Timestamp:</strong> {rec_row['timestamp']} &nbsp;|&nbsp;
            <strong>Severity:</strong> {rec_row['severity']}<br/>
            <strong>Category:</strong> {rec_row['threat']} ({rec_row['protocol']})<br/>
            <strong>Source IP:</strong> <code>{rec_row['src_ip']}</code> &rarr;
            <strong>Destination IP:</strong> <code>{rec_row['dst_ip']}</code><br/>
            <strong>Details:</strong> {rec_row['details']}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_dashboard_content(engine: MonitorEngine) -> None:
    snap = engine.analyzer.get_snapshot()
    active_page = st.session_state.get("nav_section", "Overview")

    if active_page == "Overview":
        render_overview_page(engine, snap)
    elif active_page == "Live Traffic":
        render_live_traffic_page(snap)
    elif active_page == "Threat Detection":
        render_threat_detection_page(engine, snap)
    elif active_page == "Network Analytics":
        render_network_analytics_page(engine, snap)
    elif active_page == "Alert History":
        render_alert_history_page(engine)


@st.fragment(run_every=2)
def render_live_fragment(engine: MonitorEngine) -> None:
    render_dashboard_content(engine)


def run_app() -> None:
    st.set_page_config(
        page_title="NetShield - Real-Time NIDS",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    inject_dark_theme_css()

    if "auto_refresh" not in st.session_state:
        st.session_state.auto_refresh = True

    engine = get_monitor_engine()

    # Automatically start Cloud Demo Simulator when hosted on Streamlit Community Cloud
    if is_cloud_environment() and "cloud_autostart_done" not in st.session_state:
        st.session_state.cloud_autostart_done = True
        if engine.capture.status == "Stopped":
            engine.capture.start(SIMULATOR_LABEL, SIMULATOR_DEVICE)

    h_left, h_right = st.columns([1.4, 2.6])
    with h_left:
        st.markdown("## NetShield")
        st.caption("Real-Time Network Intrusion Detection System")
    with h_right:
        st.radio(
            "Navigation",
            ["Overview", "Live Traffic", "Threat Detection", "Network Analytics", "Alert History"],
            horizontal=True,
            label_visibility="collapsed",
            key="nav_section",
        )

    render_monitoring_control_bar(engine)
    st.markdown("---")

    if st.session_state.auto_refresh and engine.capture.status == "Running":
        render_live_fragment(engine)
    else:
        render_dashboard_content(engine)


if __name__ == "__main__":
    run_app()
