import base64
import json
import queue
import ssl
import threading
import time
import urllib.error
import urllib.request
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog


# ---------------------------------------------------------------------------
# Networking layer
# ---------------------------------------------------------------------------

class F5ApiError(Exception):
    def __init__(self, parsed):
        self.parsed = parsed
        message = parsed.get("message") or str(parsed)
        super().__init__(message)


class F5Client:
    def __init__(self, host, user, password, verify_tls=False):
        self.host = host
        self.user = user
        self.password = password
        self.base = f"https://{host}/mgmt/tm/asm"
        self.ssl_context = ssl.create_default_context()
        if not verify_tls:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE

    def _auth_header(self):
        token = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        return f"Basic {token}"

    def _request(self, method, path, body=None):
        url = f"{self.base}{path}"
        data = None
        headers = {"Authorization": self._auth_header()}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=30) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = {"code": e.code, "message": raw or f"HTTP {e.code}"}
            raise F5ApiError(parsed) from e
        except urllib.error.URLError as e:
            raise F5ApiError({"code": None, "message": str(e.reason)}) from e

    def get_policies(self):
        resp = self._request("GET", "/policies?$select=name,id")
        return [(item["id"], item["name"]) for item in resp.get("items", [])]

    def get_whitelist(self, policy_id):
        resp = self._request("GET", f"/policies/{policy_id}/whitelist-ips")
        return resp.get("items", [])

    def add_whitelist_ip(self, policy_id, payload):
        return self._request("POST", f"/policies/{policy_id}/whitelist-ips", body=payload)

    def delete_whitelist_ip(self, policy_id, whitelist_id):
        return self._request("DELETE", f"/policies/{policy_id}/whitelist-ips/{whitelist_id}")

    def apply_policy(self, policy_id):
        link = f"https://{self.host}/mgmt/tm/asm/policies/{policy_id}"
        resp = self._request("POST", "/tasks/apply-policy/", body={"policyReference": {"link": link}})
        return resp.get("id")

    def get_apply_status(self, task_id):
        resp = self._request("GET", f"/tasks/apply-policy/{task_id}")
        return resp.get("status", "UNKNOWN")


# ---------------------------------------------------------------------------
# CIDR helpers
# ---------------------------------------------------------------------------

def cidr_to_mask(prefix: int) -> str:
    bits = "1" * prefix + "0" * (32 - prefix)
    octets = [bits[i:i + 8] for i in range(0, 32, 8)]
    return ".".join(str(int(o, 2)) for o in octets)


def parse_ip_input(text: str):
    text = text.strip()
    if "/" in text:
        ip, prefix_s = text.split("/", 1)
        prefix = int(prefix_s)
        if not (0 <= prefix <= 32):
            raise ValueError("CIDR prefix must be between 0 and 32")
        mask = cidr_to_mask(prefix)
    else:
        ip = text
        mask = "255.255.255.255"
    if not ip:
        raise ValueError("IP address cannot be empty")
    return ip, mask


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class App(tk.Tk):
    # F5-inspired dark palette: red/white brand accents on dark neutral surfaces.
    BG = "#09090A"
    SURFACE = "#141416"
    SURFACE_ALT = "#202124"
    BORDER = "#3A3A3D"
    TEXT = "#F5F5F5"
    MUTED = "#A7A7AD"
    ACCENT = "#E21D38"
    ACCENT_DARK = "#C41230"
    DANGER = "#E21D38"
    SUCCESS = "#2BB673"
    WARNING = "#F5B700"
    FIELD = "#0F0F11"
    FIELD_ALT = "#18181B"
    SELECT = "#8F1024"

    def __init__(self):
        super().__init__()
        self.title("F5 WAF IP Exceptions Manager by Amit Zakay")
        self.geometry("1240x820")
        self.minsize(1040, 680)
        self.configure(bg=self.BG)

        self.client = None
        self.policy_map = []  # list of (id, name)
        self.last_view = None  # remembers last list view so deletes can refresh it: {"mode": "browse"/"check", ...}
        self.result_queue = queue.Queue()

        self._configure_styles()
        self._build_shell()
        self._build_header()
        self._build_connection_card()
        self._build_main_tabs()
        self._build_status_bar()

        self.after(100, self._drain_queue)

    # ---- visual system -------------------------------------------------

    def _configure_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        self.option_add("*Font", ("Segoe UI", 10))
        self.option_add("*tearOff", False)
        self.option_add("*background", self.BG)
        self.option_add("*foreground", self.TEXT)
        self.option_add("*selectBackground", self.SELECT)
        self.option_add("*selectForeground", self.TEXT)

        style.configure("TFrame", background=self.BG)
        style.configure("Shell.TFrame", background=self.BG)
        style.configure("Card.TFrame", background=self.SURFACE, relief="flat")
        style.configure("Subtle.TFrame", background=self.SURFACE_ALT, relief="flat")

        style.configure("TLabel", background=self.BG, foreground=self.TEXT)
        style.configure("Card.TLabel", background=self.SURFACE, foreground=self.TEXT)
        style.configure("Subtle.TLabel", background=self.SURFACE_ALT, foreground=self.MUTED)
        style.configure("Title.TLabel", background=self.BG, foreground=self.TEXT, font=("Segoe UI", 20, "bold"))
        style.configure("Subtitle.TLabel", background=self.BG, foreground=self.MUTED, font=("Segoe UI", 10))
        style.configure("Section.TLabel", background=self.SURFACE, foreground=self.TEXT, font=("Segoe UI", 12, "bold"))
        style.configure("Step.TLabel", background=self.SURFACE, foreground=self.ACCENT, font=("Segoe UI", 12, "bold"))
        style.configure("Step.Subtle.TLabel", background=self.SURFACE_ALT, foreground=self.ACCENT, font=("Segoe UI", 10, "bold"))
        style.configure("Hint.TLabel", background=self.SURFACE, foreground=self.MUTED, font=("Segoe UI", 9))
        style.configure("Status.TLabel", background=self.SURFACE, foreground=self.MUTED, font=("Segoe UI", 9))
        style.configure("Badge.TLabel", background="#2A0B11", foreground="#FFD6DE", font=("Segoe UI", 9, "bold"), padding=(8, 3))
        style.configure("Connected.TLabel", background="#0F3B25", foreground="#C9F7DD", font=("Segoe UI", 9, "bold"), padding=(8, 3))
        style.configure("Disconnected.TLabel", background="#3A0B13", foreground="#FFD6DE", font=("Segoe UI", 9, "bold"), padding=(8, 3))

        style.configure(
            "TEntry",
            fieldbackground=self.FIELD,
            background=self.FIELD,
            foreground=self.TEXT,
            insertcolor=self.TEXT,
            bordercolor=self.BORDER,
            lightcolor=self.BORDER,
            darkcolor=self.BORDER,
            padding=7,
        )
        style.map(
            "TEntry",
            fieldbackground=[("focus", self.FIELD_ALT), ("disabled", "#141416")],
            foreground=[("disabled", self.MUTED)],
            bordercolor=[("focus", self.ACCENT)],
        )

        style.configure("TCheckbutton", background=self.SURFACE, foreground=self.TEXT, focuscolor=self.SURFACE)
        style.map("TCheckbutton", background=[("active", self.SURFACE)], foreground=[("disabled", self.MUTED)])
        style.configure("Subtle.TCheckbutton", background=self.SURFACE_ALT, foreground=self.TEXT, focuscolor=self.SURFACE_ALT)
        style.map("Subtle.TCheckbutton", background=[("active", self.SURFACE_ALT)], foreground=[("disabled", self.MUTED)])
        style.configure("TRadiobutton", background=self.SURFACE, foreground=self.TEXT, focuscolor=self.SURFACE)
        style.map("TRadiobutton", background=[("active", self.SURFACE)], foreground=[("disabled", self.MUTED)])
        style.configure("Subtle.TRadiobutton", background=self.SURFACE_ALT, foreground=self.TEXT, focuscolor=self.SURFACE_ALT)
        style.map("Subtle.TRadiobutton", background=[("active", self.SURFACE_ALT)], foreground=[("disabled", self.MUTED)])

        style.configure("Primary.TButton", background=self.ACCENT, foreground="#FFFFFF", font=("Segoe UI", 10, "bold"), padding=(14, 8), borderwidth=0)
        style.map("Primary.TButton", background=[("active", self.ACCENT_DARK), ("disabled", "#3A0B13")], foreground=[("disabled", self.MUTED)])
        style.configure("Secondary.TButton", background="#262629", foreground=self.TEXT, padding=(12, 8), borderwidth=0)
        style.map("Secondary.TButton", background=[("active", "#343438"), ("disabled", "#141416")], foreground=[("disabled", self.MUTED)])
        style.configure("Danger.TButton", background="#5A0B17", foreground="#FFD6DE", font=("Segoe UI", 10, "bold"), padding=(12, 8), borderwidth=0)
        style.map("Danger.TButton", background=[("active", self.ACCENT_DARK)])

        style.configure("TNotebook", background=self.BG, borderwidth=0)
        style.configure("TNotebook.Tab", background="#262629", foreground=self.MUTED, padding=(18, 9), font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", self.SURFACE), ("active", "#343438")], foreground=[("selected", self.TEXT), ("active", self.TEXT)])

        style.configure(
            "Treeview",
            background=self.FIELD,
            fieldbackground=self.FIELD,
            foreground=self.TEXT,
            rowheight=30,
            bordercolor=self.BORDER,
            borderwidth=0,
        )
        style.configure("Treeview.Heading", background="#262629", foreground=self.TEXT, font=("Segoe UI", 9, "bold"), relief="flat", padding=(8, 6))
        style.map("Treeview", background=[("selected", self.SELECT)], foreground=[("selected", "#ffffff")])

        style.configure(
            "Vertical.TScrollbar",
            background="#262629",
            troughcolor=self.BG,
            bordercolor=self.BG,
            arrowcolor=self.MUTED,
        )
        style.configure(
            "Horizontal.TScrollbar",
            background="#262629",
            troughcolor=self.BG,
            bordercolor=self.BG,
            arrowcolor=self.MUTED,
        )

    def _build_shell(self):
        self.shell = ttk.Frame(self, style="Shell.TFrame", padding=(22, 18, 22, 12))
        self.shell.pack(fill="both", expand=True)
        self.shell.columnconfigure(0, weight=1)
        self.shell.rowconfigure(2, weight=1)

    def _card(self, parent, padding=(18, 16), sticky="nsew"):
        card = ttk.Frame(parent, style="Card.TFrame", padding=padding)
        card.grid(sticky=sticky)
        return card

    def _section_header(self, parent, title, hint=None):
        ttk.Label(parent, text=title, style="Section.TLabel").pack(anchor="w")
        if hint:
            ttk.Label(parent, text=hint, style="Hint.TLabel").pack(anchor="w", pady=(2, 12))
        else:
            ttk.Frame(parent, style="Card.TFrame", height=8).pack(fill="x")

    def _build_header(self):
        header = ttk.Frame(self.shell, style="Shell.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        header.columnconfigure(0, weight=1)

        ttk.Label(header, text="F5 WAF IP Exceptions Manager", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            header,
            text="Manage IP exception lists across BIG-IP Advanced WAF policies.",
            style="Subtitle.TLabel"
        ).grid(row=1, column=0, sticky="w", pady=(3, 0))

        self.connection_state_label = ttk.Label(header, text="Not connected", style="Disconnected.TLabel")
        self.connection_state_label.grid(row=0, column=1, rowspan=2, sticky="e")

    def _build_connection_card(self):
        card = ttk.Frame(self.shell, style="Card.TFrame", padding=(18, 14))
        card.grid(row=1, column=0, sticky="ew", pady=(0, 14))
        for i in range(10):
            card.columnconfigure(i, weight=0)
        card.columnconfigure(1, weight=1)
        card.columnconfigure(3, weight=1)
        card.columnconfigure(5, weight=1)

        ttk.Label(card, text="Connection", style="Section.TLabel").grid(row=0, column=0, columnspan=8, sticky="w", pady=(0, 10))

        ttk.Label(card, text="Host / IP", style="Card.TLabel").grid(row=1, column=0, sticky="w", padx=(0, 8))
        self.host_var = tk.StringVar()
        self.host_entry = ttk.Entry(card, textvariable=self.host_var, width=28)
        self.host_entry.grid(row=1, column=1, sticky="ew", padx=(0, 14))

        ttk.Label(card, text="Username", style="Card.TLabel").grid(row=1, column=2, sticky="w", padx=(0, 8))
        self.user_var = tk.StringVar(value="admin")
        ttk.Entry(card, textvariable=self.user_var, width=18).grid(row=1, column=3, sticky="ew", padx=(0, 14))

        ttk.Label(card, text="Password", style="Card.TLabel").grid(row=1, column=4, sticky="w", padx=(0, 8))
        self.pass_var = tk.StringVar()
        ttk.Entry(card, textvariable=self.pass_var, width=18, show="*").grid(row=1, column=5, sticky="ew", padx=(0, 14))

        self.verify_tls_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(card, text="Verify TLS", variable=self.verify_tls_var).grid(row=1, column=6, sticky="w", padx=(0, 14))

        self.connect_btn = ttk.Button(card, text="Connect / Refresh", style="Primary.TButton", command=self.on_connect)
        self.connect_btn.grid(row=1, column=7, sticky="e")

        ttk.Label(
            card,
            text="Tip: leave TLS verification disabled for lab/self-signed BIG-IP certificates.",
            style="Hint.TLabel"
        ).grid(row=2, column=0, columnspan=8, sticky="w", pady=(10, 0))

    def _build_main_tabs(self):
        self.notebook = ttk.Notebook(self.shell)
        self.notebook.grid(row=2, column=0, sticky="nsew")

        self.policy_tab = ttk.Frame(self.notebook, style="Shell.TFrame", padding=(0, 14, 0, 0))
        self.ip_tab = ttk.Frame(self.notebook, style="Shell.TFrame", padding=(0, 14, 0, 0))
        self.log_tab = ttk.Frame(self.notebook, style="Shell.TFrame", padding=(0, 14, 0, 0))

        self.notebook.add(self.policy_tab, text="Policy Lookup")
        self.notebook.add(self.ip_tab, text="IP Lookup")
        self.notebook.add(self.log_tab, text="Activity Log")

        self._build_policy_lookup_tab()
        self._build_ip_lookup_tab()
        self._build_log_tab()

    def _build_policy_lookup_tab(self):
        self.policy_tab.columnconfigure(0, weight=1)
        self.policy_tab.rowconfigure(0, weight=1)

        policy_area = ttk.Frame(self.policy_tab, style="Shell.TFrame")
        policy_area.grid(row=0, column=0, sticky="nsew")
        policy_area.columnconfigure(0, weight=1)
        policy_area.rowconfigure(0, weight=1)

        self._build_policy_selector(policy_area)

    def _build_ip_lookup_tab(self):
        self.ip_tab.columnconfigure(0, weight=1)
        self.ip_tab.rowconfigure(0, weight=0)
        self.ip_tab.rowconfigure(1, weight=1)

        # Keep the add/check controls compact so the results table remains visible
        # without needing to scroll or resize the window.
        self._build_exception_details(self.ip_tab)
        self._build_manage_section(self.ip_tab)

    def _build_policy_selector(self, parent):
        left = ttk.Frame(parent, style="Card.TFrame", padding=(18, 16))
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.columnconfigure(0, weight=1)
        left.rowconfigure(2, weight=1)

        self._section_header(
            left,
            "Select policies",
            "Search and select one or more policies. Use Ctrl/Shift for multiple selections."
        )

        search_row = ttk.Frame(left, style="Card.TFrame")
        search_row.pack(fill="x", pady=(0, 10))
        search_row.columnconfigure(1, weight=1)

        ttk.Label(search_row, text="Search", style="Card.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.policy_search_var = tk.StringVar()
        self.policy_search_var.trace_add("write", lambda *_: self._apply_policy_filter())
        ttk.Entry(search_row, textvariable=self.policy_search_var).grid(row=0, column=1, sticky="ew", padx=(0, 8))
        ttk.Button(search_row, text="Clear", style="Secondary.TButton", command=lambda: self.policy_search_var.set("")).grid(row=0, column=2)

        self.policy_count_label = ttk.Label(left, text="0 policies", style="Badge.TLabel")
        self.policy_count_label.pack(anchor="w", pady=(0, 10))

        list_frame = ttk.Frame(left, style="Card.TFrame")
        list_frame.pack(fill="both", expand=True)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        self.policy_listbox = tk.Listbox(
            list_frame,
            selectmode="extended",
            exportselection=False,
            height=10,
            activestyle="none",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=self.BORDER,
            highlightcolor=self.ACCENT,
            bg=self.FIELD,
            fg=self.TEXT,
            selectbackground=self.SELECT,
            selectforeground="#ffffff",
            font=("Segoe UI", 10),
            relief="flat"
        )
        self.policy_listbox.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.policy_listbox.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.policy_listbox.config(yscrollcommand=scrollbar.set)

        self.displayed_policies = []  # (id, name) currently shown in the listbox, in display order

        policy_actions = ttk.Frame(left, style="Card.TFrame")
        policy_actions.pack(fill="x", pady=(12, 0))
        policy_actions.columnconfigure(2, weight=1)
        ttk.Button(policy_actions, text="Select All", style="Secondary.TButton", command=self.select_all_policies).grid(row=0, column=0, sticky="w")
        ttk.Button(policy_actions, text="Clear Selection", style="Secondary.TButton", command=lambda: self.policy_listbox.selection_clear(0, "end")).grid(row=0, column=1, sticky="w", padx=(8, 0))
        self.refresh_btn = ttk.Button(policy_actions, text="View All Exceptions", style="Primary.TButton", command=self.on_refresh_whitelist)
        self.refresh_btn.grid(row=0, column=3, sticky="e")

    def _build_exception_details(self, parent):
        card = ttk.Frame(parent, style="Card.TFrame", padding=(14, 12))
        card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        for col in range(4):
            card.columnconfigure(col, weight=1, uniform="ip_controls")

        ttk.Label(card, text="IP Lookup", style="Section.TLabel").grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 4))
        ttk.Label(
            card,
            text="Add exceptions to policies selected in Policy Lookup, or check all loaded policies for an existing IP entry.",
            style="Hint.TLabel"
        ).grid(row=1, column=0, columnspan=4, sticky="w", pady=(0, 8))

        # 1. Add Exception — compact IP/description input block.
        details = ttk.Frame(card, style="Subtle.TFrame", padding=(12, 10))
        details.grid(row=2, column=0, sticky="nsew", padx=(0, 6))
        details.columnconfigure(1, weight=1)
        ttk.Label(details, text="1. Add Exception", style="Step.Subtle.TLabel").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 6))

        ttk.Label(details, text="IP / CIDR", style="Subtle.TLabel").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=(0, 6))
        self.ip_var = tk.StringVar()
        ttk.Entry(details, textvariable=self.ip_var, width=22).grid(row=1, column=1, sticky="ew", pady=(0, 6))

        ttk.Label(details, text="Description", style="Subtle.TLabel").grid(row=2, column=0, sticky="w", padx=(0, 8))
        self.desc_var = tk.StringVar()
        ttk.Entry(details, textvariable=self.desc_var, width=22).grid(row=2, column=1, sticky="ew")
        ttk.Label(details, text="Example: 10.0.0.0/24", style="Subtle.TLabel").grid(row=3, column=1, sticky="w", pady=(5, 0))

        ttk.Label(details, text="— or —", style="Subtle.TLabel").grid(row=4, column=0, columnspan=2, pady=(10, 2))
        self.bulk_load_btn = ttk.Button(details, text="Load IPs from File…", style="Secondary.TButton",
                                         command=self.on_load_ip_file)
        self.bulk_load_btn.grid(row=5, column=0, columnspan=2, sticky="ew")
        ttk.Label(details, text="One IP/CIDR per line. Optional: 'ip,description'.", style="Subtle.TLabel").grid(
            row=6, column=0, columnspan=2, sticky="w", pady=(4, 0))

        self.trusted_var = tk.BooleanVar(value=False)
        self.neverlog_var = tk.BooleanVar(value=False)
        self.ignoreanom_var = tk.BooleanVar(value=False)
        self.ignorerep_var = tk.BooleanVar(value=False)
        self.neverlearn_var = tk.BooleanVar(value=False)

        # 2. Bypass Options.
        bypass = ttk.Frame(card, style="Subtle.TFrame", padding=(12, 10))
        bypass.grid(row=2, column=1, sticky="nsew", padx=6)
        ttk.Label(bypass, text="2. Bypass Options", style="Step.Subtle.TLabel").pack(anchor="w", pady=(0, 5))
        ttk.Checkbutton(bypass, text="Trusted by Policy Builder", variable=self.trusted_var, style="Subtle.TCheckbutton").pack(anchor="w", pady=1)
        ttk.Checkbutton(bypass, text="Never log requests", variable=self.neverlog_var, style="Subtle.TCheckbutton").pack(anchor="w", pady=1)
        ttk.Checkbutton(bypass, text="Ignore Brute Force protection", variable=self.ignoreanom_var, style="Subtle.TCheckbutton").pack(anchor="w", pady=1)
        ttk.Checkbutton(bypass, text="Ignore IP reputation", variable=self.ignorerep_var, style="Subtle.TCheckbutton").pack(anchor="w", pady=1)
        ttk.Checkbutton(bypass, text="Never learn requests", variable=self.neverlearn_var, style="Subtle.TCheckbutton").pack(anchor="w", pady=1)

        # 3. Block Behavior.
        block = ttk.Frame(card, style="Subtle.TFrame", padding=(12, 10))
        block.grid(row=2, column=2, sticky="nsew", padx=6)
        ttk.Label(block, text="3. Block Behavior", style="Step.Subtle.TLabel").pack(anchor="w", pady=(0, 5))
        self.block_var = tk.StringVar(value="policy-default")
        ttk.Radiobutton(block, text="Policy default", variable=self.block_var, value="policy-default", style="Subtle.TRadiobutton").pack(anchor="w", pady=1)
        ttk.Radiobutton(block, text="Never block this IP", variable=self.block_var, value="never", style="Subtle.TRadiobutton").pack(anchor="w", pady=1)
        ttk.Radiobutton(block, text="Always block this IP", variable=self.block_var, value="always", style="Subtle.TRadiobutton").pack(anchor="w", pady=1)

        # 4. Add Exception — action block.
        action = ttk.Frame(card, style="Subtle.TFrame", padding=(12, 10))
        action.grid(row=2, column=3, sticky="nsew", padx=(6, 0))
        action.columnconfigure(0, weight=1)
        ttk.Label(action, text="4. Add Exception", style="Step.Subtle.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 7))
        self.apply_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(action, text="Apply after adding", variable=self.apply_var, style="Subtle.TCheckbutton").grid(row=1, column=0, sticky="w", pady=(0, 10))
        self.submit_btn = ttk.Button(action, text="Add Exception", style="Primary.TButton", command=self.on_submit)
        self.submit_btn.grid(row=2, column=0, sticky="ew")
        ttk.Label(action, text="Uses selected policies", style="Subtle.TLabel").grid(row=3, column=0, sticky="w", pady=(8, 0))

    def _build_manage_section(self, parent):
        table_card = ttk.Frame(parent, style="Card.TFrame", padding=(14, 12))
        table_card.grid(row=1, column=0, sticky="nsew")
        table_card.columnconfigure(0, weight=1)
        table_card.rowconfigure(2, weight=1)

        header = ttk.Frame(table_card, style="Card.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="Existing exceptions / Check results", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            header,
            text="Check All Policies loads matching rows into the table below. Select any result row and delete it if needed.",
            style="Hint.TLabel"
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        search_row = ttk.Frame(table_card, style="Card.TFrame")
        search_row.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        search_row.columnconfigure(1, weight=1)
        ttk.Label(search_row, text="IP filter", style="Card.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.check_ip_var = tk.StringVar()
        ttk.Entry(search_row, textvariable=self.check_ip_var, width=24).grid(row=0, column=1, sticky="ew", padx=(0, 8))
        self.check_ip_btn = ttk.Button(search_row, text="Check All Policies", style="Secondary.TButton", command=self.on_check_ip)
        self.check_ip_btn.grid(row=0, column=2, padx=(0, 8))
        self.result_count_label = ttk.Label(search_row, text="No results loaded", style="Badge.TLabel")
        self.result_count_label.grid(row=0, column=3, sticky="e")

        tree_frame = ttk.Frame(table_card, style="Card.TFrame")
        tree_frame.grid(row=2, column=0, sticky="nsew")
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        columns = ("policy", "ip", "mask", "block", "trustedPB", "neverLog", "ignoreAnom", "ignoreRep", "neverLearn", "description")
        headings = {
            "policy": "Policy", "ip": "IP Address", "mask": "Mask", "block": "Block",
            "trustedPB": "Trusted", "neverLog": "Never Log", "ignoreAnom": "Ignore Anom",
            "ignoreRep": "Ignore Rep", "neverLearn": "Never Learn", "description": "Description",
        }
        widths = {
            "policy": 170, "ip": 118, "mask": 118, "block": 105, "trustedPB": 76,
            "neverLog": 86, "ignoreAnom": 92, "ignoreRep": 86, "neverLearn": 92, "description": 230,
        }
        left_aligned = {"policy", "ip", "mask", "description"}

        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="extended", height=14)
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], minwidth=66, anchor="w" if col in left_aligned else "center")
        self.tree.grid(row=0, column=0, sticky="nsew")

        tree_scroll_y = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        tree_scroll_y.grid(row=0, column=1, sticky="ns")
        tree_scroll_x = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        tree_scroll_x.grid(row=1, column=0, sticky="ew")
        self.tree.config(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)

        self.whitelist_entries = {}  # iid -> (policy_id, policy_name, whitelist_id, ip, mask)

        actions = ttk.Frame(table_card, style="Card.TFrame")
        actions.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        actions.columnconfigure(0, weight=1)

        ttk.Label(actions, text="Select one or more rows from View All Exceptions or Check All Policies results.", style="Hint.TLabel").grid(row=0, column=0, sticky="w")
        self.delete_apply_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(actions, text="Apply after deleting", variable=self.delete_apply_var).grid(row=0, column=1, sticky="e", padx=(0, 10))
        self.delete_btn = ttk.Button(actions, text="Delete Selected", style="Danger.TButton", command=self.on_delete_selected)
        self.delete_btn.grid(row=0, column=2, sticky="e")

    def _build_log_tab(self):
        self.log_tab.columnconfigure(0, weight=1)
        self.log_tab.rowconfigure(0, weight=1)

        card = ttk.Frame(self.log_tab, style="Card.TFrame", padding=(18, 16))
        card.grid(row=0, column=0, sticky="nsew")
        card.columnconfigure(0, weight=1)
        card.rowconfigure(1, weight=1)

        ttk.Label(card, text="Activity log", style="Section.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 10))

        self.log = scrolledtext.ScrolledText(
            card,
            height=16,
            state="disabled",
            wrap="word",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=self.BORDER,
            highlightcolor=self.ACCENT,
            bg=self.FIELD,
            fg=self.TEXT,
            insertbackground=self.TEXT,
            font=("Consolas", 10),
            relief="flat"
        )
        self.log.grid(row=1, column=0, sticky="nsew")

        log_actions = ttk.Frame(card, style="Card.TFrame")
        log_actions.grid(row=2, column=0, sticky="e", pady=(12, 0))
        ttk.Button(log_actions, text="Clear Log", style="Secondary.TButton", command=self.clear_log).pack(side="right")

    def _build_status_bar(self):
        bar = ttk.Frame(self.shell, style="Card.TFrame", padding=(12, 8))
        bar.grid(row=3, column=0, sticky="ew", pady=(12, 0))
        bar.columnconfigure(0, weight=1)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(bar, textvariable=self.status_var, style="Status.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(bar, text="F5 WAF IP Exceptions Manager by Amit Zakay", style="Badge.TLabel").grid(row=0, column=1, sticky="e")

    # ---- logging -------------------------------------------------------

    def log_msg(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")
        self.status_var.set(text[:140] if text else "Ready")

    def clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        self.status_var.set("Log cleared")

    # ---- queue draining (background thread -> GUI thread) --------------

    def _drain_queue(self):
        try:
            while True:
                func, args = self.result_queue.get_nowait()
                func(*args)
        except queue.Empty:
            pass
        self.after(100, self._drain_queue)

    def run_async(self, target, *args):
        threading.Thread(target=target, args=args, daemon=True).start()

    # ---- policy list helpers ------------------------------------------

    def _apply_policy_filter(self):
        # Keep whatever was already selected (by id) selected after refiltering,
        # so searching for several policies one at a time and ticking each off
        # does not lose earlier picks.
        selected_ids = {self.displayed_policies[i][0] for i in self.policy_listbox.curselection()}

        term = self.policy_search_var.get().strip().lower()
        if term:
            filtered = [(pid, pname) for pid, pname in self.policy_map if term in pname.lower() or term in pid.lower()]
        else:
            filtered = list(self.policy_map)

        self.policy_listbox.delete(0, "end")
        self.displayed_policies = filtered
        for pid, pname in filtered:
            self.policy_listbox.insert("end", f"{pname}    ({pid})")
        for i, (pid, _pname) in enumerate(filtered):
            if pid in selected_ids:
                self.policy_listbox.selection_set(i)

        total = len(self.policy_map)
        if term:
            self.policy_count_label.config(text=f"{len(filtered)} of {total} shown")
        else:
            self.policy_count_label.config(text=f"{total} policies")

    def select_all_policies(self):
        self.policy_listbox.selection_set(0, "end")

    def get_selected_policies(self):
        idxs = self.policy_listbox.curselection()
        return [self.displayed_policies[i] for i in idxs]

    # ---- handlers ------------------------------------------------------

    def on_connect(self):
        host = self.host_var.get().strip()
        user = self.user_var.get().strip()
        pwd = self.pass_var.get()
        if not host or not user:
            messagebox.showerror("Missing info", "Host and username are required.")
            return
        self.client = F5Client(host, user, pwd, verify_tls=self.verify_tls_var.get())
        self.connect_btn.config(state="disabled", text="Connecting...")
        self.connection_state_label.config(text="Connecting", style="Badge.TLabel")
        self.log_msg(f"Connecting to {host} ...")
        self.run_async(self._fetch_policies_thread)

    def _fetch_policies_thread(self):
        try:
            policies = self.client.get_policies()
            self.result_queue.put((self._on_policies_loaded, (policies,)))
        except F5ApiError as e:
            self.result_queue.put((self._on_error, (f"Failed to fetch policies: {e}",)))
        finally:
            self.result_queue.put((lambda: self.connect_btn.config(state="normal", text="Connect / Refresh"), ()))

    def _on_policies_loaded(self, policies):
        self.policy_map = policies
        self._apply_policy_filter()
        self.connection_state_label.config(text="Connected", style="Connected.TLabel")
        self.log_msg(f"Loaded {len(policies)} policies.")

    def _on_error(self, message):
        self.connection_state_label.config(text="Not connected", style="Disconnected.TLabel")
        self.log_msg("ERROR: " + message)
        messagebox.showerror("Error", message)

    def on_refresh_whitelist(self):
        if not self.client:
            messagebox.showwarning("Not connected", "Connect to a BIG-IP first.")
            return
        selected = self.get_selected_policies()
        if not selected:
            messagebox.showwarning("No selection", "Select at least one policy first in the Policy Lookup tab.")
            return
        self.last_view = {"mode": "browse", "selected": selected}
        self.notebook.select(self.ip_tab)
        self.refresh_btn.config(state="disabled", text="Loading...")
        self.run_async(self._refresh_whitelist_thread, selected)

    def _refresh_whitelist_thread(self, selected):
        self.result_queue.put((self._clear_tree, ()))
        total_count = 0
        for pid, pname in selected:
            try:
                items = self.client.get_whitelist(pid)
                total_count += len(items)
                self.result_queue.put((self.log_msg, (f"Loaded {len(items)} exception(s) for '{pname}'.",)))
                for item in items:
                    self.result_queue.put((self._insert_tree_row, (pid, pname, item)))
            except F5ApiError as e:
                self.result_queue.put((self.log_msg, (f"ERROR retrieving whitelist for {pname}: {e}",)))
        self.result_queue.put((self._set_result_count, (f"{total_count} row(s) loaded",)))
        self.result_queue.put((lambda: self.refresh_btn.config(state="normal", text="View All Exceptions"), ()))

    def on_check_ip(self):
        if not self.client:
            messagebox.showwarning("Not connected", "Connect to a BIG-IP first.")
            return
        if not self.policy_map:
            messagebox.showwarning("No policies loaded", "Click 'Connect / Refresh' first.")
            return
        ip_filter = self.check_ip_var.get().strip()
        if not ip_filter:
            messagebox.showwarning("Missing IP", "Enter an IP address or part of one to check for.")
            return
        self.last_view = {"mode": "check", "ip_filter": ip_filter}
        self.check_ip_btn.config(state="disabled", text="Checking...")
        self.run_async(self._check_ip_thread, ip_filter)

    def _check_ip_thread(self, ip_filter):
        self.result_queue.put((self._clear_tree, ()))
        match_count = 0
        for pid, pname in self.policy_map:
            try:
                items = self.client.get_whitelist(pid)
            except F5ApiError as e:
                self.result_queue.put((self.log_msg, (f"ERROR checking '{pname}': {e}",)))
                continue
            for item in items:
                if ip_filter in item.get("ipAddress", ""):
                    self.result_queue.put((self._insert_tree_row, (pid, pname, item)))
                    match_count += 1
        self.result_queue.put((self._set_result_count, (f"{match_count} match(es)",)))
        self.result_queue.put((self.log_msg, (f"Checked {len(self.policy_map)} policies for '{ip_filter}': {match_count} match(es) found. Select matching rows in the table and click Delete Selected if needed.",)))
        self.result_queue.put((lambda: self.check_ip_btn.config(state="normal", text="Check All Policies"), ()))

    def _redo_last_view(self):
        """Re-run whichever list view was last shown so the table remains accurate after delete."""
        if not self.last_view:
            return
        if self.last_view.get("mode") == "browse":
            selected = self.last_view.get("selected") or []
            if selected:
                self._refresh_whitelist_thread(selected)
        elif self.last_view.get("mode") == "check":
            ip_filter = self.last_view.get("ip_filter")
            if ip_filter:
                self._check_ip_thread(ip_filter)

    def _clear_tree(self):
        self.tree.delete(*self.tree.get_children())
        self.whitelist_entries.clear()
        self._set_result_count("No results loaded")

    def _set_result_count(self, text):
        if hasattr(self, "result_count_label"):
            self.result_count_label.config(text=text)

    def _insert_tree_row(self, pid, pname, item):
        wid = item.get("id", "")
        iid = f"{pid}::{wid}"
        values = (
            pname,
            item.get("ipAddress", ""),
            item.get("ipMask", ""),
            item.get("blockRequests", ""),
            self._bool_label(item.get("trustedByPolicyBuilder", False)),
            self._bool_label(item.get("neverLogRequests", False)),
            self._bool_label(item.get("ignoreAnomalies", False)),
            self._bool_label(item.get("ignoreIpReputation", False)),
            self._bool_label(item.get("neverLearnRequests", False)),
            item.get("description", ""),
        )
        if not self.tree.exists(iid):
            self.tree.insert("", "end", iid=iid, values=values)
        self.whitelist_entries[iid] = (pid, pname, wid, item.get("ipAddress", ""), item.get("ipMask", ""))

    @staticmethod
    def _bool_label(value):
        return "Yes" if bool(value) else "No"

    def on_delete_selected(self):
        if not self.client:
            messagebox.showwarning("Not connected", "Connect to a BIG-IP first.")
            return
        iids = self.tree.selection()
        if not iids:
            messagebox.showwarning("No selection", "Select one or more rows in the list above to delete.")
            return
        entries = [self.whitelist_entries[iid] for iid in iids if iid in self.whitelist_entries]
        if not entries:
            return

        summary = "Delete the following exception(s)?\n\n" + "\n".join(
            f"  - {ip} from '{pname}'" for (_pid, pname, _wid, ip, _mask) in entries
        ) + f"\n\nApply policy after deleting: {self.delete_apply_var.get()}"
        if not messagebox.askyesno("Confirm delete", summary):
            return

        self.delete_btn.config(state="disabled", text="Deleting...")
        self.run_async(self._delete_thread, entries, self.delete_apply_var.get())

    def _delete_thread(self, entries, do_apply):
        touched = {}  # policy_id -> policy_name, for policies with a successful deletion
        for pid, pname, wid, ip, mask in entries:
            self.result_queue.put((self.log_msg, (f"\n>>> Deleting {ip}/{mask} from '{pname}'",)))
            try:
                self.client.delete_whitelist_ip(pid, wid)
                self.result_queue.put((self.log_msg, ("  Deleted.",)))
                touched[pid] = pname
            except F5ApiError as e:
                self.result_queue.put((self.log_msg, (f"  ERROR deleting: {e}",)))

        if do_apply:
            for pid, pname in touched.items():
                try:
                    task_id = self.client.apply_policy(pid)
                    self.result_queue.put((self.log_msg, (f"  Applying policy '{pname}' (task {task_id}) ...",)))
                    self._poll_apply(task_id, pname)
                except F5ApiError as e:
                    self.result_queue.put((self.log_msg, (f"  ERROR applying policy '{pname}': {e}",)))
        elif touched:
            self.result_queue.put((
                self.log_msg,
                ("  Skipped apply — remember to apply the affected policies for the deletion(s) to take effect.",)
            ))

        self.result_queue.put((lambda: self.delete_btn.config(state="normal", text="Delete Selected"), ()))
        self._redo_last_view()

    # ---- bulk import from file -----------------------------------------

    def _current_option_defaults(self):
        """Snapshot of the main Add Exception form's current option values,
        used to seed every IP loaded from a file before the wizard runs."""
        return {
            "trustedByPolicyBuilder": self.trusted_var.get(),
            "neverLogRequests": self.neverlog_var.get(),
            "ignoreAnomalies": self.ignoreanom_var.get(),
            "ignoreIpReputation": self.ignorerep_var.get(),
            "neverLearnRequests": self.neverlearn_var.get(),
            "blockRequests": self.block_var.get(),
        }

    @staticmethod
    def _parse_ip_list_file(path):
        """Parse a text file of IPs/CIDRs (optionally 'ip,description' per line,
        '#' comments and blank lines ignored). Returns (entries, errors)."""
        entries = []
        errors = []
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, raw_line in enumerate(fh, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if "," in line:
                    ip_part, desc_part = line.split(",", 1)
                    ip_part, desc_part = ip_part.strip(), desc_part.strip()
                else:
                    ip_part, desc_part = line, ""
                try:
                    ip, mask = parse_ip_input(ip_part)
                except ValueError as e:
                    errors.append(f"Line {lineno}: '{line}' — {e}")
                    continue
                entries.append({"ip": ip, "mask": mask, "description": desc_part})
        return entries, errors

    def on_load_ip_file(self):
        path = filedialog.askopenfilename(
            title="Select a text file with one IP/CIDR per line",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            entries, errors = self._parse_ip_list_file(path)
        except OSError as e:
            messagebox.showerror("Could not read file", str(e))
            return

        if not entries:
            messagebox.showerror(
                "No valid IPs found",
                "No valid IP addresses were found in that file."
                + (f"\n\n{len(errors)} line(s) could not be parsed." if errors else "")
            )
            return

        if errors:
            preview = "\n".join(errors[:10])
            more = f"\n…and {len(errors) - 10} more." if len(errors) > 10 else ""
            messagebox.showwarning(
                "Some lines were skipped",
                f"Loaded {len(entries)} valid IP(s). {len(errors)} line(s) could not be "
                f"parsed and were skipped:\n\n{preview}{more}"
            )

        self.log_msg(f"Loaded {len(entries)} IP(s) from file: {path}")
        BulkImportDialog(self, entries)

    def _bulk_submit_thread(self, entries, selected, do_apply):
        for pid, pname in selected:
            self.result_queue.put((self.log_msg, (f"\n>>> {pname} ({pid}) — adding {len(entries)} exception(s)",)))
            added = 0
            for entry in entries:
                payload = {
                    "ipAddress": entry["ip"],
                    "ipMask": entry["mask"],
                    "blockRequests": entry["blockRequests"],
                    "trustedByPolicyBuilder": entry["trustedByPolicyBuilder"],
                    "neverLogRequests": entry["neverLogRequests"],
                    "ignoreAnomalies": entry["ignoreAnomalies"],
                    "ignoreIpReputation": entry["ignoreIpReputation"],
                    "neverLearnRequests": entry["neverLearnRequests"],
                    "description": entry.get("description", ""),
                }
                try:
                    resp = self.client.add_whitelist_ip(pid, payload)
                    added += 1
                    self.result_queue.put((
                        self.log_msg, (f"  + {entry['ip']}/{entry['mask']} (id: {resp.get('id', 'unknown')})",)
                    ))
                except F5ApiError as e:
                    self.result_queue.put((self.log_msg, (f"  ERROR adding {entry['ip']}/{entry['mask']}: {e}",)))

            self.result_queue.put((self.log_msg, (f"  {added} of {len(entries)} added to '{pname}'.",)))

            if do_apply:
                try:
                    task_id = self.client.apply_policy(pid)
                    self.result_queue.put((self.log_msg, (f"  Applying policy '{pname}' (task {task_id}) ...",)))
                    self._poll_apply(task_id, pname)
                except F5ApiError as e:
                    self.result_queue.put((self.log_msg, (f"  ERROR applying policy '{pname}': {e}",)))
            else:
                self.result_queue.put((
                    self.log_msg,
                    (f"  Skipped apply for '{pname}' — remember to apply for changes to take effect.",)
                ))

        self.last_view = {"mode": "browse", "selected": selected}
        self._refresh_whitelist_thread(selected)

    def on_submit(self):
        if not self.client:
            messagebox.showwarning("Not connected", "Connect to a BIG-IP first.")
            return
        selected = self.get_selected_policies()
        if not selected:
            messagebox.showwarning("No selection", "Select at least one policy first in the Policy Lookup tab.")
            return
        ip_text = self.ip_var.get().strip()
        if not ip_text:
            messagebox.showwarning("Missing IP", "Enter an IP address or CIDR range.")
            return
        try:
            ip_addr, ip_mask = parse_ip_input(ip_text)
        except ValueError as e:
            messagebox.showerror("Invalid input", str(e))
            return

        payload = {
            "ipAddress": ip_addr,
            "ipMask": ip_mask,
            "blockRequests": self.block_var.get(),
            "trustedByPolicyBuilder": self.trusted_var.get(),
            "neverLogRequests": self.neverlog_var.get(),
            "ignoreAnomalies": self.ignoreanom_var.get(),
            "ignoreIpReputation": self.ignorerep_var.get(),
            "neverLearnRequests": self.neverlearn_var.get(),
            "description": self.desc_var.get().strip(),
        }

        summary = (
            f"About to add {ip_addr}/{ip_mask} to {len(selected)} policy/policies:\n"
            + "\n".join(f"  - {n}" for _, n in selected)
            + f"\n\nblockRequests={payload['blockRequests']}, "
              f"trustedPB={payload['trustedByPolicyBuilder']}, "
              f"neverLog={payload['neverLogRequests']}, "
              f"ignoreAnom={payload['ignoreAnomalies']}, "
              f"ignoreRep={payload['ignoreIpReputation']}, "
              f"neverLearn={payload['neverLearnRequests']}\n\n"
              f"Apply policy after adding: {self.apply_var.get()}\n\nProceed?"
        )
        if not messagebox.askyesno("Confirm", summary):
            return

        self.submit_btn.config(state="disabled", text="Working...")
        self.run_async(self._submit_thread, selected, payload, self.apply_var.get())

    def _submit_thread(self, selected, payload, do_apply):
        for pid, pname in selected:
            self.result_queue.put((self.log_msg, (f"\n>>> {pname} ({pid})",)))
            try:
                resp = self.client.add_whitelist_ip(pid, payload)
                self.result_queue.put((self.log_msg, (f"  Added exception (id: {resp.get('id', 'unknown')}).",)))
            except F5ApiError as e:
                self.result_queue.put((self.log_msg, (f"  ERROR adding exception: {e}",)))
                continue

            if do_apply:
                try:
                    task_id = self.client.apply_policy(pid)
                    self.result_queue.put((self.log_msg, (f"  Applying policy (task {task_id}) ...",)))
                    self._poll_apply(task_id, pname)
                except F5ApiError as e:
                    self.result_queue.put((self.log_msg, (f"  ERROR applying policy: {e}",)))
            else:
                self.result_queue.put((
                    self.log_msg,
                    ("  Skipped apply — remember to apply this policy for the change to take effect.",)
                ))

        self.result_queue.put((lambda: self.submit_btn.config(state="normal", text="Add Exception"), ()))
        self.last_view = {"mode": "browse", "selected": selected}
        self._refresh_whitelist_thread(selected)

    def _poll_apply(self, task_id, pname):
        while True:
            try:
                status = self.client.get_apply_status(task_id)
            except F5ApiError as e:
                self.result_queue.put((self.log_msg, (f"  ERROR checking apply status: {e}",)))
                return
            if status == "COMPLETED":
                self.result_queue.put((self.log_msg, (f"  Policy '{pname}' applied successfully.",)))
                return
            if status == "FAILURE":
                self.result_queue.put((self.log_msg, (f"  Policy '{pname}' apply FAILED.",)))
                return
            time.sleep(2)


class BulkImportDialog(tk.Toplevel):
    """Step-by-step wizard for a list of IPs loaded from a file.

    Walks through each IP one at a time asking what to do with it (pre-filled
    with the main form's current settings), with a shortcut to apply the same
    bypass/block settings to every IP in the list instead of stepping through
    each one individually. Ends on a review screen before anything is sent.
    """

    def __init__(self, app: "App", entries):
        super().__init__(app)
        self.app = app
        self.entries = entries
        self.index = 0

        defaults = app._current_option_defaults()
        for entry in self.entries:
            for key, value in defaults.items():
                entry.setdefault(key, value)

        self.title(f"Bulk Import — {len(entries)} IP(s)")
        self.geometry("640x580")
        self.minsize(580, 500)
        self.configure(bg=app.BG)
        self.transient(app)
        self.grab_set()

        self.desc_var = tk.StringVar()
        self.trusted_var = tk.BooleanVar()
        self.neverlog_var = tk.BooleanVar()
        self.ignoreanom_var = tk.BooleanVar()
        self.ignorerep_var = tk.BooleanVar()
        self.neverlearn_var = tk.BooleanVar()
        self.block_var = tk.StringVar()
        self.apply_after_var = tk.BooleanVar(value=True)

        self.body = ttk.Frame(self, style="Shell.TFrame", padding=16)
        self.body.pack(fill="both", expand=True)
        self.body.columnconfigure(0, weight=1)
        self.body.rowconfigure(1, weight=1)

        self._build_step_view()
        self._show_entry(0)

    # ---- per-IP step view ------------------------------------------

    def _build_step_view(self):
        for child in self.body.winfo_children():
            child.destroy()

        header = ttk.Frame(self.body, style="Shell.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        header.columnconfigure(0, weight=1)
        self.progress_label = ttk.Label(header, text="", style="Section.TLabel")
        self.progress_label.grid(row=0, column=0, sticky="w")
        target_names = ", ".join(n for _, n in self.app.get_selected_policies()) or "(none selected yet)"
        ttk.Label(header, text=f"Target polic(ies): {target_names}", style="Hint.TLabel").grid(
            row=1, column=0, sticky="w", pady=(2, 0))

        card = ttk.Frame(self.body, style="Card.TFrame", padding=16)
        card.grid(row=1, column=0, sticky="nsew")
        card.columnconfigure(1, weight=1)

        self.ip_label = ttk.Label(card, text="", style="Step.TLabel")
        self.ip_label.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))

        ttk.Label(card, text="Description", style="Card.TLabel").grid(row=1, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(card, textvariable=self.desc_var).grid(row=1, column=1, sticky="ew", pady=(0, 10))

        bypass = ttk.Frame(card, style="Subtle.TFrame", padding=(12, 10))
        bypass.grid(row=2, column=0, sticky="nsew", padx=(0, 6), pady=(0, 10))
        ttk.Label(bypass, text="Bypass Options", style="Step.Subtle.TLabel").pack(anchor="w", pady=(0, 5))
        ttk.Checkbutton(bypass, text="Trusted by Policy Builder", variable=self.trusted_var,
                         style="Subtle.TCheckbutton").pack(anchor="w", pady=1)
        ttk.Checkbutton(bypass, text="Never log requests", variable=self.neverlog_var,
                         style="Subtle.TCheckbutton").pack(anchor="w", pady=1)
        ttk.Checkbutton(bypass, text="Ignore anomalies", variable=self.ignoreanom_var,
                         style="Subtle.TCheckbutton").pack(anchor="w", pady=1)
        ttk.Checkbutton(bypass, text="Ignore IP reputation", variable=self.ignorerep_var,
                         style="Subtle.TCheckbutton").pack(anchor="w", pady=1)
        ttk.Checkbutton(bypass, text="Never learn requests", variable=self.neverlearn_var,
                         style="Subtle.TCheckbutton").pack(anchor="w", pady=1)

        block = ttk.Frame(card, style="Subtle.TFrame", padding=(12, 10))
        block.grid(row=2, column=1, sticky="nsew", padx=(6, 0), pady=(0, 10))
        ttk.Label(block, text="Block Behavior", style="Step.Subtle.TLabel").pack(anchor="w", pady=(0, 5))
        ttk.Radiobutton(block, text="Policy default", variable=self.block_var, value="policy-default",
                        style="Subtle.TRadiobutton").pack(anchor="w", pady=1)
        ttk.Radiobutton(block, text="Never block this IP", variable=self.block_var, value="never",
                        style="Subtle.TRadiobutton").pack(anchor="w", pady=1)
        ttk.Radiobutton(block, text="Always block this IP", variable=self.block_var, value="always",
                        style="Subtle.TRadiobutton").pack(anchor="w", pady=1)

        ttk.Button(card, text="Apply these settings to ALL IPs in the list ▸", style="Primary.TButton",
                   command=self.on_apply_to_all).grid(row=3, column=0, columnspan=2, sticky="ew", pady=(4, 4))
        ttk.Label(
            card,
            text="Skips the per-IP walkthrough — uses the bypass/block settings above for every "
                 "IP (descriptions stay as loaded from the file).",
            style="Hint.TLabel"
        ).grid(row=4, column=0, columnspan=2, sticky="w")

        nav = ttk.Frame(self.body, style="Shell.TFrame")
        nav.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        nav.columnconfigure(1, weight=1)
        ttk.Button(nav, text="Cancel", style="Secondary.TButton", command=self.destroy).grid(row=0, column=0, sticky="w")
        self.back_btn = ttk.Button(nav, text="◂ Back", style="Secondary.TButton", command=self.on_back)
        self.back_btn.grid(row=0, column=2, sticky="e", padx=(0, 8))
        self.next_btn = ttk.Button(nav, text="Next ▸", style="Primary.TButton", command=self.on_next)
        self.next_btn.grid(row=0, column=3, sticky="e")

    def _show_entry(self, idx):
        self.index = idx
        entry = self.entries[idx]
        self.progress_label.config(text=f"IP {idx + 1} of {len(self.entries)}")
        self.ip_label.config(text=f"{entry['ip']} / {entry['mask']}")
        self.desc_var.set(entry.get("description", ""))
        self.trusted_var.set(entry["trustedByPolicyBuilder"])
        self.neverlog_var.set(entry["neverLogRequests"])
        self.ignoreanom_var.set(entry["ignoreAnomalies"])
        self.ignorerep_var.set(entry["ignoreIpReputation"])
        self.neverlearn_var.set(entry["neverLearnRequests"])
        self.block_var.set(entry["blockRequests"])
        self.back_btn.config(state="normal" if idx > 0 else "disabled")
        self.next_btn.config(text="Review & Submit ▸" if idx == len(self.entries) - 1 else "Next ▸")

    def _save_current(self):
        entry = self.entries[self.index]
        entry["description"] = self.desc_var.get().strip()
        entry["trustedByPolicyBuilder"] = self.trusted_var.get()
        entry["neverLogRequests"] = self.neverlog_var.get()
        entry["ignoreAnomalies"] = self.ignoreanom_var.get()
        entry["ignoreIpReputation"] = self.ignorerep_var.get()
        entry["neverLearnRequests"] = self.neverlearn_var.get()
        entry["blockRequests"] = self.block_var.get()

    def on_next(self):
        self._save_current()
        if self.index == len(self.entries) - 1:
            self._build_review_view()
        else:
            self._show_entry(self.index + 1)

    def on_back(self):
        self._save_current()
        if self.index > 0:
            self._show_entry(self.index - 1)

    def on_apply_to_all(self):
        self._save_current()
        current = self.entries[self.index]
        shared_keys = ("trustedByPolicyBuilder", "neverLogRequests", "ignoreAnomalies",
                       "ignoreIpReputation", "neverLearnRequests", "blockRequests")
        shared_values = {k: current[k] for k in shared_keys}
        for entry in self.entries:
            entry.update(shared_values)
        self._build_review_view()

    # ---- review / submit -------------------------------------------

    def _build_review_view(self):
        for child in self.body.winfo_children():
            child.destroy()

        header = ttk.Frame(self.body, style="Shell.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text=f"Review — {len(self.entries)} IP(s)", style="Section.TLabel").grid(
            row=0, column=0, sticky="w")
        target_names = ", ".join(n for _, n in self.app.get_selected_policies()) or "(none — go select a policy first)"
        ttk.Label(header, text=f"Will be added to: {target_names}", style="Hint.TLabel").grid(
            row=1, column=0, sticky="w", pady=(2, 0))

        table_frame = ttk.Frame(self.body, style="Card.TFrame", padding=10)
        table_frame.grid(row=1, column=0, sticky="nsew")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        columns = ("ip", "mask", "block", "trustedPB", "neverLog", "ignoreAnom", "ignoreRep", "neverLearn", "description")
        headings = {
            "ip": "IP Address", "mask": "Mask", "block": "Block", "trustedPB": "Trusted",
            "neverLog": "Never Log", "ignoreAnom": "Ignore Anom", "ignoreRep": "Ignore Rep",
            "neverLearn": "Never Learn", "description": "Description",
        }
        widths = {"ip": 110, "mask": 110, "block": 95, "trustedPB": 70, "neverLog": 80,
                  "ignoreAnom": 85, "ignoreRep": 80, "neverLearn": 85, "description": 160}

        tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=10)
        for col in columns:
            tree.heading(col, text=headings[col])
            tree.column(col, width=widths[col], anchor="w" if col in ("ip", "mask", "description") else "center")
        tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        tree.config(yscrollcommand=scroll.set)

        for entry in self.entries:
            tree.insert("", "end", values=(
                entry["ip"], entry["mask"], entry["blockRequests"],
                "Yes" if entry["trustedByPolicyBuilder"] else "No",
                "Yes" if entry["neverLogRequests"] else "No",
                "Yes" if entry["ignoreAnomalies"] else "No",
                "Yes" if entry["ignoreIpReputation"] else "No",
                "Yes" if entry["neverLearnRequests"] else "No",
                entry.get("description", ""),
            ))

        footer = ttk.Frame(self.body, style="Shell.TFrame")
        footer.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        footer.columnconfigure(1, weight=1)
        ttk.Checkbutton(footer, text="Apply policy after adding", variable=self.apply_after_var).grid(
            row=0, column=0, sticky="w")
        ttk.Button(footer, text="◂ Back to Edit", style="Secondary.TButton",
                   command=self._back_to_edit).grid(row=0, column=2, sticky="e", padx=(0, 8))
        ttk.Button(footer, text=f"Submit {len(self.entries)} IP(s)", style="Primary.TButton",
                   command=self.on_submit_all).grid(row=0, column=3, sticky="e")

    def _back_to_edit(self):
        self._build_step_view()
        self._show_entry(min(self.index, len(self.entries) - 1))

    def on_submit_all(self):
        selected = self.app.get_selected_policies()
        if not selected:
            messagebox.showwarning(
                "No policy selected",
                "Go to the Policy Lookup tab and select at least one policy first.",
                parent=self,
            )
            return
        summary = (
            f"Add {len(self.entries)} IP(s) to {len(selected)} polic(ies):\n"
            + "\n".join(f"  - {n}" for _, n in selected)
            + f"\n\nApply policy after adding: {self.apply_after_var.get()}\n\nProceed?"
        )
        if not messagebox.askyesno("Confirm bulk import", summary, parent=self):
            return

        entries_copy = [dict(e) for e in self.entries]
        do_apply = self.apply_after_var.get()
        self.app.log_msg(f"Bulk import started: {len(entries_copy)} IP(s) -> {len(selected)} polic(ies).")
        self.app.run_async(self.app._bulk_submit_thread, entries_copy, selected, do_apply)
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.mainloop()
