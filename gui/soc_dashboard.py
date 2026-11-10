import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

from elasticsearch import Elasticsearch


# ============================================================
# SENTINEL//COMMAND CENTER
# Lightweight Python SOC Dashboard
# Reads alert data from the existing Elasticsearch SIEM.
# ============================================================

ES_URL = "http://localhost:9200"
ALERT_INDEX = "siem-alerts-*"
REFRESH_MS = 30000

BG = "#070d18"
PANEL = "#0d1728"
PANEL_2 = "#101d31"
BORDER = "#233654"
TEXT = "#d7e5f5"
MUTED = "#7890ad"
CYAN = "#18d7ff"
GREEN = "#32e6a1"
RED = "#ff4f6d"
ORANGE = "#ffbf4d"
PURPLE = "#a88cff"
WHITE = "#f5f8fc"


class SentinelDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("SENTINEL//COMMAND CENTER")
        self.root.geometry("1380x820")
        self.root.minsize(1120, 700)
        self.root.configure(bg=BG)

        self.es = None
        self.alerts = []
        self.last_refresh = "Never"

        self.setup_style()
        self.build_ui()
        self.connect_and_refresh()

        self.root.after(REFRESH_MS, self.auto_refresh)

    # --------------------------------------------------------
    # STYLE
    # --------------------------------------------------------
    def setup_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Treeview",
            background="#08111f",
            foreground=TEXT,
            fieldbackground="#08111f",
            bordercolor=BORDER,
            rowheight=31,
            font=("Consolas", 9),
        )
        style.configure(
            "Treeview.Heading",
            background=PANEL_2,
            foreground=CYAN,
            relief="flat",
            font=("Consolas", 9, "bold"),
        )
        style.map(
            "Treeview",
            background=[("selected", "#16314a")],
            foreground=[("selected", WHITE)],
        )

    # --------------------------------------------------------
    # HELPERS
    # --------------------------------------------------------
    def panel(self, parent, **kwargs):
        return tk.Frame(
            parent,
            bg=kwargs.pop("bg", PANEL),
            highlightbackground=BORDER,
            highlightthickness=1,
            bd=0,
        )

    def label(self, parent, text, size=10, color=TEXT, bold=False, **kwargs):
        return tk.Label(
            parent,
            text=text,
            bg=kwargs.pop("bg", parent.cget("bg")),
            fg=color,
            font=("Consolas", size, "bold" if bold else "normal"),
            **kwargs,
        )

    def button(self, parent, text, command, color=CYAN, width=13):
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=PANEL_2,
            fg=color,
            activebackground="#17314b",
            activeforeground=WHITE,
            relief="flat",
            bd=0,
            highlightbackground=color,
            highlightcolor=color,
            highlightthickness=1,
            font=("Consolas", 9, "bold"),
            cursor="hand2",
            width=width,
            padx=8,
            pady=7,
        )

    # --------------------------------------------------------
    # UI
    # --------------------------------------------------------
    def build_ui(self):
        # Header
        header = tk.Frame(self.root, bg=BG, height=76)
        header.pack(fill="x", padx=18, pady=(12, 0))
        header.pack_propagate(False)

        left = tk.Frame(header, bg=BG)
        left.pack(side="left", fill="y")

        self.label(
            left,
            "SENTINEL//COMMAND CENTER",
            24,
            CYAN,
            True,
            bg=BG,
            anchor="w",
        ).pack(anchor="w")

        self.label(
            left,
            "SECURITY OPERATIONS CENTER  /  PYTHON SOC INTERFACE",
            9,
            MUTED,
            False,
            bg=BG,
            anchor="w",
        ).pack(anchor="w", pady=(3, 0))

        right = tk.Frame(header, bg=BG)
        right.pack(side="right", fill="y")

        self.status_dot = self.label(
            right, "●  CONNECTING", 10, ORANGE, True, bg=BG
        )
        self.status_dot.pack(anchor="e", pady=(7, 0))

        self.es_label = self.label(
            right, "ELASTICSEARCH  /  localhost:9200",
            8, MUTED, False, bg=BG
        )
        self.es_label.pack(anchor="e")

        # Main layout
        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=18, pady=10)

        sidebar = self.panel(body, bg="#091222")
        sidebar.pack(side="left", fill="y", padx=(0, 10))
        sidebar.configure(width=175)
        sidebar.pack_propagate(False)

        self.build_sidebar(sidebar)

        content = tk.Frame(body, bg=BG)
        content.pack(side="left", fill="both", expand=True)

        self.build_content(content)

        # Bottom status
        footer = tk.Frame(self.root, bg=BG, height=28)
        footer.pack(fill="x", padx=18, pady=(0, 7))
        footer.pack_propagate(False)

        self.footer_label = self.label(
            footer,
            "SYSTEM READY  /  LOCAL PROCESSING",
            8,
            GREEN,
            True,
            bg=BG,
        )
        self.footer_label.pack(side="left")

        self.time_label = self.label(
            footer,
            "LAST REFRESH: --",
            8,
            MUTED,
            False,
            bg=BG,
        )
        self.time_label.pack(side="right")

    def build_sidebar(self, parent):
        self.label(
            parent, "SENTINEL", 16, WHITE, True, bg="#091222"
        ).pack(anchor="w", padx=18, pady=(22, 0))

        self.label(
            parent, "SOC SECURITY", 8, MUTED, False, bg="#091222"
        ).pack(anchor="w", padx=18, pady=(2, 25))

        items = [
            ("01", "OVERVIEW"),
            ("02", "ALERT STREAM"),
            ("03", "IP INVESTIGATION"),
            ("04", "USER INVESTIGATION"),
            ("05", "DETECTIONS"),
            ("06", "SYSTEM STATUS"),
        ]

        for number, name in items:
            row = tk.Frame(parent, bg="#091222", height=38)
            row.pack(fill="x", padx=8, pady=1)
            row.pack_propagate(False)

            self.label(
                row, number, 8, CYAN, True, bg="#091222", width=4
            ).pack(side="left", padx=(7, 0))

            self.label(
                row, name, 8, TEXT, False, bg="#091222"
            ).pack(side="left")

        # System telemetry
        self.label(
            parent, "SYSTEM TELEMETRY", 8, CYAN, True, bg="#091222"
        ).pack(anchor="w", padx=18, pady=(28, 8))

        self.telemetry = tk.Text(
            parent,
            height=12,
            width=20,
            bg="#050b14",
            fg=MUTED,
            insertbackground=CYAN,
            relief="flat",
            bd=0,
            font=("Consolas", 8),
            padx=8,
            pady=8,
        )
        self.telemetry.pack(fill="x", padx=10)
        self.telemetry.insert(
            "1.0",
            "[SYSTEM] Sentinel initialized\n"
            "[SYSTEM] Waiting for Elasticsearch...\n"
            "[INFO] Local processing enabled\n",
        )
        self.telemetry.configure(state="disabled")

        self.label(
            parent,
            "NO CLOUD TRANSFER",
            7,
            GREEN,
            True,
            bg="#091222",
        ).pack(side="bottom", pady=(0, 18))

    def build_content(self, parent):
        # Metric cards
        metrics = tk.Frame(parent, bg=BG)
        metrics.pack(fill="x")

        self.metric_vars = {}
        metric_defs = [
            ("TOTAL ALERTS", "total", CYAN),
            ("CRITICAL RISK", "critical", RED),
            ("HIGH SEVERITY", "high", ORANGE),
            ("MEDIUM SEVERITY", "medium", PURPLE),
            ("MAX RISK SCORE", "maxrisk", GREEN),
        ]

        for title, key, color in metric_defs:
            card = self.panel(metrics, bg=PANEL)
            card.pack(side="left", fill="x", expand=True, padx=(0, 7))

            self.label(
                card, title, 8, MUTED, True, bg=PANEL
            ).pack(anchor="w", padx=14, pady=(11, 0))

            var = tk.StringVar(value="--")
            self.metric_vars[key] = var

            tk.Label(
                card,
                textvariable=var,
                bg=PANEL,
                fg=color,
                font=("Consolas", 20, "bold"),
                anchor="w",
            ).pack(anchor="w", padx=14, pady=(2, 11))

        # Alert stream
        stream_panel = self.panel(parent, bg=PANEL)
        stream_panel.pack(fill="both", expand=True, pady=(10, 10))

        titlebar = tk.Frame(stream_panel, bg=PANEL, height=42)
        titlebar.pack(fill="x")
        titlebar.pack_propagate(False)

        self.label(
            titlebar, "01  /  LIVE ALERT STREAM", 10, CYAN, True, bg=PANEL
        ).pack(side="left", padx=14, pady=11)

        self.search_var = tk.StringVar()
        search = tk.Entry(
            titlebar,
            textvariable=self.search_var,
            bg="#07101d",
            fg=TEXT,
            insertbackground=CYAN,
            relief="flat",
            highlightbackground=BORDER,
            highlightthickness=1,
            font=("Consolas", 9),
            width=27,
        )
        search.pack(side="right", padx=(5, 7), pady=8)
        search.bind("<Return>", lambda event: self.filter_alerts())

        self.button(
            titlebar, "SEARCH", self.filter_alerts, CYAN, 9
        ).pack(side="right", pady=7)

        self.button(
            titlebar, "REFRESH", self.refresh_data, GREEN, 9
        ).pack(side="right", padx=7, pady=7)

        # Table
        table_frame = tk.Frame(stream_panel, bg=PANEL)
        table_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        columns = (
            "type",
            "severity",
            "ip",
            "user",
            "risk",
            "risksev",
            "time",
        )

        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        headings = {
            "type": "DETECTION TYPE",
            "severity": "SEVERITY",
            "ip": "SOURCE IP",
            "user": "USERNAME",
            "risk": "RISK",
            "risksev": "RISK LEVEL",
            "time": "TIMESTAMP",
        }

        widths = {
            "type": 205,
            "severity": 90,
            "ip": 135,
            "user": 130,
            "risk": 65,
            "risksev": 90,
            "time": 165,
        }

        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor="w")

        scrollbar = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.tree.yview
        )
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.tree.tag_configure("critical", foreground=RED)
        self.tree.tag_configure("high", foreground=ORANGE)
        self.tree.tag_configure("medium", foreground=PURPLE)
        self.tree.tag_configure("low", foreground=GREEN)

        self.tree.bind("<<TreeviewSelect>>", self.show_selected_alert)

        # Lower investigation area
        lower = tk.Frame(parent, bg=BG, height=175)
        lower.pack(fill="x")
        lower.pack_propagate(False)

        self.build_investigation(lower)
        self.build_detection_summary(lower)

    def build_investigation(self, parent):
        p = self.panel(parent, bg=PANEL)
        p.pack(side="left", fill="both", expand=True, padx=(0, 5))

        self.label(
            p, "02  /  INVESTIGATION CONSOLE", 9, CYAN, True, bg=PANEL
        ).pack(anchor="w", padx=13, pady=(10, 6))

        controls = tk.Frame(p, bg=PANEL)
        controls.pack(fill="x", padx=12)

        self.label(
            controls, "IP", 8, MUTED, True, bg=PANEL
        ).pack(side="left")

        self.ip_var = tk.StringVar()
        tk.Entry(
            controls,
            textvariable=self.ip_var,
            bg="#07101d",
            fg=TEXT,
            insertbackground=CYAN,
            relief="flat",
            highlightbackground=BORDER,
            highlightthickness=1,
            font=("Consolas", 9),
            width=18,
        ).pack(side="left", padx=(5, 10))

        self.label(
            controls, "USER", 8, MUTED, True, bg=PANEL
        ).pack(side="left")

        self.user_var = tk.StringVar()
        tk.Entry(
            controls,
            textvariable=self.user_var,
            bg="#07101d",
            fg=TEXT,
            insertbackground=CYAN,
            relief="flat",
            highlightbackground=BORDER,
            highlightthickness=1,
            font=("Consolas", 9),
            width=16,
        ).pack(side="left", padx=(5, 10))

        self.button(
            controls, "INVESTIGATE", self.investigate, CYAN, 13
        ).pack(side="left")

        self.investigation_text = tk.Text(
            p,
            height=4,
            bg="#050b14",
            fg=TEXT,
            relief="flat",
            bd=0,
            font=("Consolas", 8),
            padx=8,
            pady=6,
        )
        self.investigation_text.pack(fill="both", expand=True, padx=12, pady=8)
        self.investigation_text.insert(
            "1.0",
            "Enter an IP or username and press INVESTIGATE.\n"
        )
        self.investigation_text.configure(state="disabled")

    def build_detection_summary(self, parent):
        p = self.panel(parent, bg=PANEL)
        p.pack(side="left", fill="both", expand=True, padx=(5, 0))

        self.label(
            p, "03  /  DETECTION INTELLIGENCE", 9, CYAN, True, bg=PANEL
        ).pack(anchor="w", padx=13, pady=(10, 5))

        self.detection_text = tk.Text(
            p,
            height=7,
            bg="#050b14",
            fg=TEXT,
            relief="flat",
            bd=0,
            font=("Consolas", 8),
            padx=8,
            pady=6,
        )
        self.detection_text.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        self.detection_text.insert(
            "1.0",
            "Waiting for alert data...\n"
        )
        self.detection_text.configure(state="disabled")

    # --------------------------------------------------------
    # ELASTICSEARCH
    # --------------------------------------------------------
    def connect_and_refresh(self):
        try:
            self.es = Elasticsearch(ES_URL, request_timeout=5)
            if not self.es.ping():
                raise RuntimeError("Elasticsearch ping failed")

            self.set_status(True)
            self.refresh_data()

        except Exception as exc:
            self.set_status(False, str(exc))
            self.show_error_state(str(exc))

    def refresh_data(self):
        if self.es is None:
            self.connect_and_refresh()
            return

        try:
            response = self.es.search(
                index=ALERT_INDEX,
                size=300,
                sort=[{"stored_at": {"order": "desc"}}],
                query={"match_all": {}},
            )

            self.alerts = []
            for hit in response.get("hits", {}).get("hits", []):
                doc = hit.get("_source", {})
                doc["_id"] = hit.get("_id", "")
                self.alerts.append(doc)

            self.update_metrics()
            self.populate_table(self.alerts)
            self.update_detection_summary()
            self.last_refresh = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.time_label.configure(text=f"LAST REFRESH: {self.last_refresh}")

            self.set_status(True)
            self.write_telemetry(
                f"[OK] Elasticsearch connected\n"
                f"[OK] Alerts loaded: {len(self.alerts)}\n"
                f"[OK] Index: {ALERT_INDEX}\n"
                f"[INFO] Last refresh: {self.last_refresh}\n"
            )

        except Exception as exc:
            self.set_status(False, str(exc))
            self.write_telemetry(
                f"[ERROR] Elasticsearch query failed\n{exc}\n"
            )

    def update_metrics(self):
        total = len(self.alerts)

        critical = sum(
            1 for a in self.alerts
            if str(a.get("risk_severity", "")).upper() == "CRITICAL"
        )

        high = sum(
            1 for a in self.alerts
            if str(a.get("severity", "")).upper() == "HIGH"
        )

        medium = sum(
            1 for a in self.alerts
            if str(a.get("severity", "")).upper() == "MEDIUM"
        )

        risks = []
        for a in self.alerts:
            try:
                risks.append(int(a.get("risk_score", 0)))
            except (TypeError, ValueError):
                pass

        maxrisk = max(risks) if risks else 0

        self.metric_vars["total"].set(str(total))
        self.metric_vars["critical"].set(str(critical))
        self.metric_vars["high"].set(str(high))
        self.metric_vars["medium"].set(str(medium))
        self.metric_vars["maxrisk"].set(str(maxrisk))

    # --------------------------------------------------------
    # TABLE
    # --------------------------------------------------------
    def populate_table(self, data):
        for item in self.tree.get_children():
            self.tree.delete(item)

        for alert in data:
            alert_type = str(alert.get("alert_type", alert.get("detection_type", "-")))
            severity = str(alert.get("severity", "-")).upper()
            ip = str(alert.get("source_ip", "-"))
            user = str(alert.get("username", "-"))

            try:
                risk = int(alert.get("risk_score", 0))
            except (TypeError, ValueError):
                risk = 0

            risk_level = str(
                alert.get("risk_severity", alert.get("severity", "-"))
            ).upper()

            timestamp = str(
                alert.get("stored_at", alert.get("@timestamp", "-"))
            )

            if len(timestamp) > 19:
                timestamp = timestamp[:19].replace("T", " ")

            tag = "low"
            if risk_level == "CRITICAL" or risk >= 80:
                tag = "critical"
            elif severity == "HIGH" or risk >= 60:
                tag = "high"
            elif severity == "MEDIUM" or risk >= 30:
                tag = "medium"

            self.tree.insert(
                "",
                "end",
                values=(
                    alert_type,
                    severity,
                    ip,
                    user,
                    risk,
                    risk_level,
                    timestamp,
                ),
                tags=(tag,),
            )

    def filter_alerts(self):
        query = self.search_var.get().strip().lower()

        if not query:
            self.populate_table(self.alerts)
            return

        filtered = []
        for alert in self.alerts:
            blob = " ".join(
                str(v).lower()
                for v in alert.values()
            )
            if query in blob:
                filtered.append(alert)

        self.populate_table(filtered)

    def show_selected_alert(self, _event=None):
        selection = self.tree.selection()
        if not selection:
            return

        values = self.tree.item(selection[0], "values")
        if not values:
            return

        alert_type, severity, ip, user, risk, risk_level, timestamp = values

        self.write_investigation(
            f"SELECTED ALERT\n"
            f"--------------------------------\n"
            f"Detection : {alert_type}\n"
            f"Severity  : {severity}\n"
            f"Risk      : {risk} ({risk_level})\n"
            f"Source IP : {ip}\n"
            f"Username  : {user}\n"
            f"Time      : {timestamp}\n"
        )

    # --------------------------------------------------------
    # INVESTIGATION
    # --------------------------------------------------------
    def investigate(self):
        ip = self.ip_var.get().strip()
        user = self.user_var.get().strip()

        if not ip and not user:
            self.write_investigation(
                "Enter an IP address or username first."
            )
            return

        matches = []

        for alert in self.alerts:
            if ip and str(alert.get("source_ip", "")) == ip:
                matches.append(alert)
            elif user and str(alert.get("username", "")) == user:
                matches.append(alert)

        if not matches:
            self.write_investigation(
                "NO MATCHING ALERTS FOUND\n"
                "--------------------------------\n"
                f"IP       : {ip or '-'}\n"
                f"Username : {user or '-'}\n"
            )
            return

        lines = [
            "INVESTIGATION RESULT",
            "--------------------------------",
            f"Matching alerts : {len(matches)}",
        ]

        ips = sorted(
            {str(a.get("source_ip", "-")) for a in matches}
        )
        users = sorted(
            {str(a.get("username", "-")) for a in matches}
        )
        detections = sorted(
            {str(a.get("alert_type", "-")) for a in matches}
        )

        lines.append(f"Source IPs       : {', '.join(ips)}")
        lines.append(f"Users            : {', '.join(users)}")
        lines.append(f"Detections       : {', '.join(detections)}")

        self.write_investigation("\n".join(lines))

    # --------------------------------------------------------
    # SUMMARIES / STATUS
    # --------------------------------------------------------
    def update_detection_summary(self):
        counts = {}

        for alert in self.alerts:
            name = str(
                alert.get("alert_type", alert.get("detection_type", "unknown"))
            )
            counts[name] = counts.get(name, 0) + 1

        ordered = sorted(counts.items(), key=lambda x: (-x[1], x[0]))

        lines = []
        for name, count in ordered:
            lines.append(f"{name:<32} {count:>3}")

        if not lines:
            lines = ["No stored alerts found."]

        self.set_text(self.detection_text, "\n".join(lines))

    def set_status(self, online, detail=""):
        if online:
            self.status_dot.configure(text="●  LIVE ACTIVE", fg=GREEN)
            self.footer_label.configure(
                text="SYSTEM READY  /  ELASTICSEARCH ONLINE",
                fg=GREEN,
            )
        else:
            self.status_dot.configure(text="●  OFFLINE", fg=RED)
            self.footer_label.configure(
                text="SYSTEM WARNING  /  ELASTICSEARCH UNAVAILABLE",
                fg=RED,
            )

    def write_telemetry(self, text):
        self.set_text(self.telemetry, text)

    def write_investigation(self, text):
        self.set_text(self.investigation_text, text)

    @staticmethod
    def set_text(widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def show_error_state(self, error):
        self.update_metrics()
        self.set_text(
            self.detection_text,
            "Elasticsearch connection unavailable.\n\n"
            "Make sure the SIEM stack is running.\n\n"
            f"Error: {error}",
        )

    def auto_refresh(self):
        self.refresh_data()
        self.root.after(REFRESH_MS, self.auto_refresh)


def main():
    root = tk.Tk()
    SentinelDashboard(root)
    root.mainloop()


if __name__ == "__main__":
    main()
