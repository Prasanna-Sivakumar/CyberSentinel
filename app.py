import os
import sqlite3
import pandas as pd
import streamlit as st
import plotly.express as px

# =====================================
# PAGE CONFIGURATION
# =====================================
st.set_page_config(
    page_title="CyberSentinel SOC",
    page_icon="🛡️",
    layout="wide"
)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybersentinel.db")

# =====================================
# DATABASE CONNECTION
# =====================================
def read_table(conn, table_name):
    """Read a table if it exists; otherwise return an empty DataFrame."""
    exists = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,)
    ).fetchone()
    if not exists:
        return pd.DataFrame()
    return pd.read_sql_query(f'SELECT * FROM "{table_name}"', conn)


@st.cache_data(ttl=10)
def load_data():
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(
            f"Database not found at {DB_PATH}. Keep cybersentinel.db beside app.py."
        )

    conn = sqlite3.connect(DB_PATH)
    try:
        events = read_table(conn, "network_events_v2")
        alerts = read_table(conn, "security_alerts_v2")
        metrics = read_table(conn, "evaluation_metrics")
        ml_predictions = read_table(conn, "ml_predictions_v3")
        ml_metrics = read_table(conn, "ml_model_metrics_v3")
    finally:
        conn.close()

    return events, alerts, metrics, ml_predictions, ml_metrics


try:
    events, alerts, metrics, ml_predictions, ml_metrics = load_data()
except Exception as e:
    st.error(f"Database loading failed: {e}")
    st.stop()

# Normalize common column names in the ML metrics table
if not ml_metrics.empty:
    ml_metrics.columns = [str(c).strip() for c in ml_metrics.columns]
    if "model" not in ml_metrics.columns and "index" in ml_metrics.columns:
        ml_metrics = ml_metrics.rename(columns={"index": "model"})

# =====================================
# SIDEBAR
# =====================================
st.sidebar.title("🛡️ CyberSentinel")
st.sidebar.caption("Network Security Analytics")

page = st.sidebar.radio(
    "Navigation",
    [
        "Security Overview",
        "Network Analytics",
        "Threat Intelligence",
        "IP Investigation",
        "Security Alerts",
        "Detection Performance",
        "Machine Learning Analytics"
    ]
)

st.sidebar.divider()
st.sidebar.caption("Simulation-based analysis")
st.sidebar.caption("CyberSentinel v2.0 | ML-enabled")

# =====================================
# SECURITY OVERVIEW
# =====================================
if page == "Security Overview":
    st.title("🛡️ Security Operations Center")
    st.caption("Network monitoring and threat analytics dashboard")

    total_events = len(events)
    total_alerts = len(alerts)
    suspicious_ips = alerts["source_ip"].nunique() if (
        not alerts.empty and "source_ip" in alerts.columns
    ) else 0
    detected_events = int(pd.to_numeric(events["detected"], errors="coerce").fillna(0).sum()) if (
        not events.empty and "detected" in events.columns
    ) else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Network Events", f"{total_events:,}")
    c2.metric("Security Alerts", f"{total_alerts:,}")
    c3.metric("Suspicious IPs", suspicious_ips)
    c4.metric("Flagged Events", f"{detected_events:,}")

    st.divider()
    left, right = st.columns(2)

    with left:
        st.subheader("Network Protocol Distribution")
        if not events.empty and "protocol" in events.columns:
            protocol_data = events["protocol"].value_counts().rename_axis("Protocol").reset_index(name="Events")
            fig = px.pie(protocol_data, names="Protocol", values="Events", hole=0.5)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No protocol data available.")

    with right:
        st.subheader("Threat Severity Distribution")
        if not alerts.empty and "severity" in alerts.columns:
            severity_data = alerts["severity"].value_counts().rename_axis("Severity").reset_index(name="Alerts")
            fig = px.bar(severity_data, x="Severity", y="Alerts", color="Severity")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No security alerts available.")

    st.subheader("Latest Security Alerts")
    if not alerts.empty:
        sort_col = "score" if "score" in alerts.columns else alerts.columns[0]
        st.dataframe(
            alerts.sort_values(sort_col, ascending=False).head(10),
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No security alerts available.")

# =====================================
# NETWORK ANALYTICS
# =====================================
elif page == "Network Analytics":
    st.title("Network Traffic Analytics")
    left, right = st.columns(2)

    with left:
        st.subheader("Protocol Distribution")
        if not events.empty and "protocol" in events.columns:
            protocol_data = events["protocol"].value_counts().rename_axis("Protocol").reset_index(name="Events")
            fig = px.bar(protocol_data, x="Protocol", y="Events")
            st.plotly_chart(fig, use_container_width=True)

    with right:
        st.subheader("Top Destination Ports")
        if not events.empty and "dst_port" in events.columns:
            port_data = (
                events.groupby("dst_port").size().reset_index(name="Events")
                .sort_values("Events", ascending=False).head(10)
            )
            fig = px.bar(port_data, x="dst_port", y="Events")
            st.plotly_chart(fig, use_container_width=True)

    st.subheader("Top Source IP Addresses")
    if not events.empty and "src_ip" in events.columns:
        ip_data = (
            events.groupby("src_ip").size().reset_index(name="Events")
            .sort_values("Events", ascending=False).head(10)
        )
        st.dataframe(ip_data, use_container_width=True, hide_index=True)

# =====================================
# THREAT INTELLIGENCE
# =====================================
elif page == "Threat Intelligence":
    st.title("Threat Intelligence")
    if not alerts.empty and "threat" in alerts.columns:
        threat_counts = alerts["threat"].value_counts().rename_axis("Threat").reset_index(name="Count")
        fig = px.bar(threat_counts, x="Threat", y="Count", color="Threat")
        st.plotly_chart(fig, use_container_width=True)
        st.subheader("Threat Records")
        st.dataframe(alerts, use_container_width=True, hide_index=True)
    else:
        st.info("No threats detected.")

# =====================================
# IP INVESTIGATION
# =====================================
elif page == "IP Investigation":
    st.title("IP Address Investigation")
    if events.empty or "src_ip" not in events.columns:
        st.info("No network event data available.")
    else:
        available_ips = sorted(events["src_ip"].dropna().unique().tolist())
        selected_ip = st.selectbox("Select source IP", available_ips)
        ip_events = events[events["src_ip"] == selected_ip]
        ip_alerts = alerts[alerts["source_ip"] == selected_ip] if (
            not alerts.empty and "source_ip" in alerts.columns
        ) else pd.DataFrame()

        c1, c2, c3 = st.columns(3)
        c1.metric("Network Events", len(ip_events))
        c2.metric("Security Alerts", len(ip_alerts))
        c3.metric(
            "Detected Events",
            int(pd.to_numeric(ip_events["detected"], errors="coerce").fillna(0).sum())
            if "detected" in ip_events.columns else 0
        )

        st.subheader("Destination IPs")
        st.dataframe(
            ip_events.groupby("dst_ip").size().reset_index(name="Events"),
            use_container_width=True,
            hide_index=True
        )
        st.subheader("Security Alerts for Selected IP")
        st.dataframe(ip_alerts, use_container_width=True, hide_index=True)

# =====================================
# SECURITY ALERTS
# =====================================
elif page == "Security Alerts":
    st.title("Security Alert Management")
    if not alerts.empty:
        severity_options = ["All"] + sorted(alerts["severity"].dropna().unique().tolist())
        selected_severity = st.selectbox("Filter by severity", severity_options)
        filtered = alerts.copy()

        if selected_severity != "All":
            filtered = filtered[filtered["severity"] == selected_severity]

        search_ip = st.text_input("Search source IP")
        if search_ip:
            filtered = filtered[
                filtered["source_ip"].astype(str).str.contains(search_ip, na=False)
            ]

        st.write("Matching alerts:", len(filtered))
        sort_col = "score" if "score" in filtered.columns else filtered.columns[0]
        st.dataframe(
            filtered.sort_values(sort_col, ascending=False),
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No security alerts available.")

# =====================================
# DETECTION PERFORMANCE
# =====================================
elif page == "Detection Performance":
    st.title("Rule-Based Detection Performance")
    if not metrics.empty:
        row = metrics.iloc[-1]

        # Support both the original schema (tp/fp/tn/fn) and display names.
        def metric_value(*names, default=0):
            for name in names:
                if name in row.index and pd.notna(row[name]):
                    return row[name]
            return default

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Accuracy", f"{float(metric_value('accuracy')) * 100:.2f}%")
        c2.metric("Precision", f"{float(metric_value('precision')) * 100:.2f}%")
        c3.metric("Recall", f"{float(metric_value('recall')) * 100:.2f}%")
        c4.metric("F1 Score", f"{float(metric_value('f1_score')) * 100:.2f}%")

        st.subheader("Confusion Matrix Values")
        confusion = pd.DataFrame({
            "Outcome": ["True Positive", "True Negative", "False Positive", "False Negative"],
            "Count": [
                metric_value("true_positive", "tp"),
                metric_value("true_negative", "tn"),
                metric_value("false_positive", "fp"),
                metric_value("false_negative", "fn")
            ]
        })
        fig = px.bar(confusion, x="Outcome", y="Count", color="Outcome")
        st.plotly_chart(fig, use_container_width=True)
        st.metric(
            "False Positive Rate",
            f"{float(metric_value('false_positive_rate')) * 100:.2f}%"
        )
    else:
        st.warning("No evaluation metrics found.")

# =====================================
# MACHINE LEARNING ANALYTICS
# =====================================
elif page == "Machine Learning Analytics":
    st.title("🤖 Machine Learning Analytics")
    st.caption("Behavioural Isolation Forest compared with rule-based detection")

    if ml_predictions.empty or ml_metrics.empty:
        st.warning(
            "ML results were not found. Run the ML SQLite storage cell in Colab, "
            "then refresh this dashboard."
        )
    else:
        # Make numeric columns safe for charting and calculations.
        for col in [
            "actual_label", "ml_prediction", "rule_prediction", "anomaly_score"
        ]:
            if col in ml_predictions.columns:
                ml_predictions[col] = pd.to_numeric(
                    ml_predictions[col], errors="coerce"
                )

        metrics_view = ml_metrics.copy()
        # SQLite preserves the DataFrame column names from the storage cell.
        rename_map = {
            "Accuracy": "Accuracy",
            "Precision": "Precision",
            "Recall": "Recall",
            "F1 Score": "F1 Score",
            "False Positives": "False Positives",
            "False Negatives": "False Negatives",
            "True Positives": "True Positives",
            "True Negatives": "True Negatives"
        }

        required = ["model", "Accuracy", "Precision", "Recall", "F1 Score"]
        missing = [c for c in required if c not in metrics_view.columns]

        if missing:
            st.error(
                "The ML metrics table is missing expected columns: "
                + ", ".join(missing)
            )
        else:
            for col in ["Accuracy", "Precision", "Recall", "F1 Score"]:
                metrics_view[col] = pd.to_numeric(metrics_view[col], errors="coerce")

            st.subheader("Model Performance")
            ml_row = metrics_view[
                metrics_view["model"].astype(str).str.contains("Isolation Forest", case=False, na=False)
            ]
            rule_row = metrics_view[
                metrics_view["model"].astype(str).str.contains("Rule-Based", case=False, na=False)
            ]

            if not ml_row.empty:
                r = ml_row.iloc[0]
                a, b, c, d = st.columns(4)
                a.metric("ML Accuracy", f"{r['Accuracy'] * 100:.2f}%")
                b.metric("ML Precision", f"{r['Precision'] * 100:.2f}%")
                c.metric("ML Recall", f"{r['Recall'] * 100:.2f}%")
                d.metric("ML F1 Score", f"{r['F1 Score'] * 100:.2f}%")

            if not rule_row.empty:
                r = rule_row.iloc[0]
                a, b, c, d = st.columns(4)
                a.metric("Rule Accuracy", f"{r['Accuracy'] * 100:.2f}%")
                b.metric("Rule Precision", f"{r['Precision'] * 100:.2f}%")
                c.metric("Rule Recall", f"{r['Recall'] * 100:.2f}%")
                d.metric("Rule F1 Score", f"{r['F1 Score'] * 100:.2f}%")

            st.divider()
            st.subheader("ML vs Rule-Based Comparison")

            chart_data = metrics_view.melt(
                id_vars="model",
                value_vars=["Accuracy", "Precision", "Recall", "F1 Score"],
                var_name="Metric",
                value_name="Score"
            )
            fig = px.bar(
                chart_data,
                x="Metric",
                y="Score",
                color="model",
                barmode="group",
                range_y=[0, 1],
                text=chart_data["Score"].map(lambda x: f"{x:.1%}")
            )
            st.plotly_chart(fig, use_container_width=True)

            # Confusion counts comparison
            confusion_cols = [
                "True Positives", "False Positives",
                "True Negatives", "False Negatives"
            ]
            if all(col in metrics_view.columns for col in confusion_cols):
                confusion_data = metrics_view.melt(
                    id_vars="model",
                    value_vars=confusion_cols,
                    var_name="Outcome",
                    value_name="Events"
                )
                fig = px.bar(
                    confusion_data,
                    x="Outcome",
                    y="Events",
                    color="model",
                    barmode="group"
                )
                st.subheader("Confusion Counts")
                st.plotly_chart(fig, use_container_width=True)

            st.divider()
            st.subheader("ML Anomaly Detection Summary")

            total_tested = len(ml_predictions)
            anomalies = int((ml_predictions["ml_prediction"] == 1).sum()) if (
                "ml_prediction" in ml_predictions.columns
            ) else 0
            normal_predictions = total_tested - anomalies

            a, b, c = st.columns(3)
            a.metric("Test Events", f"{total_tested:,}")
            b.metric("ML Anomalies", f"{anomalies:,}")
            b.metric("Predicted Normal", f"{normal_predictions:,}")
            c.metric(
                "False Positives",
                int((metrics_view.iloc[0]["False Positives"]))
                if "False Positives" in metrics_view.columns else "N/A"
            )

            st.subheader("Event-Level Investigation")
            if {"actual_label", "ml_prediction", "rule_prediction"}.issubset(ml_predictions.columns):
                filter_type = st.selectbox(
                    "Filter predictions",
                    ["All test events", "ML anomalies only", "ML false positives", "ML missed attacks"]
                )
                view = ml_predictions.copy()

                if filter_type == "ML anomalies only":
                    view = view[view["ml_prediction"] == 1]
                elif filter_type == "ML false positives":
                    view = view[
                        (view["actual_label"] == 0) &
                        (view["ml_prediction"] == 1)
                    ]
                elif filter_type == "ML missed attacks":
                    view = view[
                        (view["actual_label"] == 1) &
                        (view["ml_prediction"] == 0)
                    ]

                display_cols = [
                    c for c in [
                        "event_id", "actual_label", "ml_prediction",
                        "rule_prediction", "anomaly_score"
                    ] if c in view.columns
                ]
                st.write("Matching events:", len(view))
                st.dataframe(
                    view[display_cols].sort_values(
                        "anomaly_score", ascending=True
                    ) if "anomaly_score" in display_cols else view[display_cols],
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.info("The stored prediction table does not contain all expected fields.")

            st.caption(
                "Evaluation uses the held-out simulated test set. ML anomaly predictions "
                "are experimental signals, not proof of malicious activity."
            )
