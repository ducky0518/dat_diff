#!/usr/bin/env python3

import os
import json
import gzip
import zipfile
import hashlib
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, Tuple, List, Set, Optional

import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog, messagebox

import customtkinter as ctk
import logging
logger = logging.getLogger(__name__)


APP_TITLE = "DAT Diff (by -God-like)"
PROFILE_STORE = "profiles.json"
UI_PREFS_STORE = "ui_prefs.json"

# ---- Appearance (safe before root) ----
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")
ctk.set_widget_scaling(1.15)
ctk.set_window_scaling(1.10)

# Tree colors (dark)
COLOR_BG = "#141414"
COLOR_BG_ALT = "#1B1B1B"
COLOR_FG = "#E6E6E6"
COLOR_SEL_BG = "#2D5A9E"
COLOR_SEL_FG = "#FFFFFF"
COLOR_HDR_BG = "#1F1F1F"
COLOR_HDR_FG = "#E6E6E6"
COLOR_BORDER = "#2A2A2A"

COLOR_ADDED = "#27ae60"
COLOR_REMOVED = "#e74c3c"
COLOR_CHANGED = "#f39c12"

# ---------- Data Types ----------
Checksum = Tuple[Optional[str], Optional[str], Optional[str]]  # (crc, md5, sha1)

@dataclass(frozen=True)
class RomEntry:
    game: str
    rom: str
    size: Optional[int]
    checksums: Checksum

@dataclass
class DatIndex:
    meta: Dict[str, str] = field(default_factory=dict)
    games: Set[str] = field(default_factory=set)
    by_game_rom: Dict[Tuple[str, str], RomEntry] = field(default_factory=dict)

    @staticmethod
    def from_roms(roms: List[RomEntry], meta: Dict[str, str]) -> "DatIndex":
        idx = DatIndex(meta=meta)
        for r in roms:
            idx.games.add(r.game)
            key = (r.game, r.rom)
            idx.by_game_rom[key] = r
        return idx

# ---------- Helpers: file loading ----------
def _read_single_file_from_zip(zf: zipfile.ZipFile) -> bytes:
    names = [n for n in zf.namelist() if not n.endswith("/")]
    if not names:
        raise ValueError("ZIP archive is empty.")
    preferred = [n for n in names if n.lower().endswith((".xml", ".dat"))]
    target = preferred[0] if preferred else names[0]
    with zf.open(target, "r") as f:
        return f.read()

def read_dat_bytes(path: str) -> bytes:
    lp = path.lower()
    if lp.endswith(".gz"):
        with gzip.open(path, "rb") as f:
            return f.read()
    if lp.endswith(".zip"):
        with zipfile.ZipFile(path, "r") as zf:
            return _read_single_file_from_zip(zf)
    with open(path, "rb") as f:
        return f.read()

def normalize_text(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    s = s.strip()
    return s or None

def to_int_or_none(s: Optional[str]) -> Optional[int]:
    if s is None:
        return None
    try:
        return int(s)
    except Exception:
        return None

def hash_bytes(b: bytes) -> str:
    """Return a stable hex digest (SHA-1) for a given bytes payload.
    Used to generate deterministic profile IDs from sorted game names.
    """
    return hashlib.sha1(b).hexdigest()

# ---------- Parsing ----------
def _localname(tag: str) -> str:
    """Namespace-agnostic element name, e.g. '{ns}header' -> 'header'."""
    return tag.split("}", 1)[-1].lower() if "}" in tag else tag.lower()

def _extract_header_meta(root: ET.Element) -> Dict[str, str]:
    """
    Gather header-style metadata from common places:
    - <header> (any depth, any namespace)
    - <datafile>/<header>
    - child <clrmamepro> under <header>
    - attributes on <header> or root/datafile elements
    - fallback: copy known tags seen anywhere at shallow depth
    """
    wanted = {"name", "description", "version", "date", "author", "homepage", "url", "comment"}
    meta: Dict[str, str] = {}

    # Find a <header> node (namespace-agnostic, any depth)
    header = None
    # Try common direct finds first
    for p in ("header", ".//header", ".//datafile/header"):
        try:
            h = root.find(p)
            if h is not None:
                header = h
                break
        except Exception:
            pass
    # Fallback: scan all nodes for localname == 'header'
    if header is None:
        for el in root.iter():
            if _localname(el.tag) == "header":
                header = el
                break

    def collect_from_element(el: Optional[ET.Element]):
        if el is None:
            return
        # children as elements
        for child in list(el):
            ln = _localname(child.tag)
            if ln in wanted and child.text and ln not in meta:
                v = child.text.strip()
                if v:
                    meta[ln] = v
        # attributes on this element
        for k, v in el.attrib.items():
            lk = k.lower()
            if lk in wanted and v and lk not in meta:
                meta[lk] = v.strip()

    # 1) Main header
    collect_from_element(header)

    # 2) clrmamepro block under header (some DATs put fields here)
    if header is not None:
        for child in list(header):
            if _localname(child.tag) in {"clrmamepro", "romvault"}:
                collect_from_element(child)

    # 3) Attributes on root/datafile (some DATs carry name/version here)
    collect_from_element(root)
    # Find a <datafile> node if present
    datafile = None
    for el in root.iter():
        if _localname(el.tag) == "datafile":
            datafile = el
            break
    collect_from_element(datafile)

    # 4) Last-ditch: shallow scan for common tags anywhere
    for el in root.iter():
        ln = _localname(el.tag)
        if ln in wanted and el.text and ln not in meta:
            v = el.text.strip()
            if v:
                meta[ln] = v
        # stop early if we’ve collected a good set
        if len(meta) >= 5:
            break

    return meta

def parse_dat_xml_bytes(data: bytes) -> DatIndex:
    # Robust XML load (bytes or text)
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        txt = data.decode(errors="replace")
        root = ET.fromstring(txt)

    # ---- Metadata (robust across formats/namespaces)
    meta: Dict[str, str] = _extract_header_meta(root)

    # ---- Games / ROMs parsing (kept as in your app, with small ns-agnostic tweaks)
    # Accept both <game> and <machine> (namespace-agnostic)
    game_tags: List[ET.Element] = []
    for el in root.iter():
        ln = _localname(el.tag)
        if ln in {"game", "machine"}:
            game_tags.append(el)

    roms: List[RomEntry] = []
    for g in game_tags:
        # game name: prefer @name, else <description>
        gname = normalize_text(g.attrib.get("name"))
        if not gname:
            desc_el = None
            for ch in g:
                if _localname(ch.tag) == "description":
                    desc_el = ch; break
            gname = normalize_text(desc_el.text) if (desc_el is not None and desc_el.text) else "<unknown>"

        for r in g:
            ln = _localname(r.tag)
            if ln not in ("rom", "disk"):
                continue

            rname = normalize_text(r.attrib.get("name")) or "<unnamed>"

            # CHD <disk> entries usually don't have size=; that's okay (leave None)
            size  = to_int_or_none(r.attrib.get("size"))

            # checksums: CHDs typically have sha1 (and sometimes md5), rarely crc
            crc   = normalize_text(r.attrib.get("crc"))
            md5   = normalize_text(r.attrib.get("md5"))
            sha1  = normalize_text(r.attrib.get("sha1"))

            roms.append(
                RomEntry(game=gname, rom=rname, size=size, checksums=(crc, md5, sha1))
            )

    return DatIndex.from_roms(roms, meta)


def parse_dat_file(path: str) -> DatIndex:
    raw = read_dat_bytes(path)
    return parse_dat_xml_bytes(raw)

# ---------- Diff ----------
@dataclass
class DiffResult:
    games_added: List[str]
    games_removed: List[str]
    roms_added: List[RomEntry]
    roms_removed: List[RomEntry]
    roms_changed: List[Tuple[RomEntry, RomEntry]]  # (old, new)

def diff_dat(source: DatIndex, target: DatIndex) -> DiffResult:
    games_added = sorted(list(target.games - source.games))
    games_removed = sorted(list(source.games - target.games))

    source_keys = set(source.by_game_rom.keys())
    target_keys = set(target.by_game_rom.keys())

    added_keys = target_keys - source_keys
    removed_keys = source_keys - target_keys
    common_keys = source_keys & target_keys

    roms_added = [target.by_game_rom[k] for k in sorted(added_keys)]
    roms_removed = [source.by_game_rom[k] for k in sorted(removed_keys)]

    roms_changed: List[Tuple[RomEntry, RomEntry]] = []
    for k in sorted(common_keys):
        old = source.by_game_rom[k]
        new = target.by_game_rom[k]
        if (old.size != new.size) or (old.checksums != new.checksums):
            roms_changed.append((old, new))

    return DiffResult(
        games_added=games_added,
        games_removed=games_removed,
        roms_added=roms_added,
        roms_removed=roms_removed,
        roms_changed=roms_changed,
    )

# ---------- UI Prefs ----------
UI_DEFAULTS = {
    "roms_added":   ["Game", "ROM", "Size", "CRC", "MD5", "SHA1"],
    "roms_removed": ["Game", "ROM", "Size", "CRC", "MD5", "SHA1"],
    "roms_changed": ["Game", "ROM", "Old Size", "New Size", "Old CRC", "New CRC", "Old MD5", "New MD5", "Old SHA1", "New SHA1"],
}

def load_ui_prefs() -> Dict[str, List[str]]:
    if not os.path.exists(UI_PREFS_STORE):
        return dict(UI_DEFAULTS)
    try:
        with open(UI_PREFS_STORE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            merged = dict(UI_DEFAULTS)
            for k, v in data.items():
                if isinstance(v, list):
                    merged[k] = v
            return merged
    except Exception:
        pass
    return dict(UI_DEFAULTS)

def save_ui_prefs(prefs: Dict[str, List[str]]) -> None:
    try:
        with open(UI_PREFS_STORE, "w", encoding="utf-8") as f:
            json.dump(prefs, f, indent=2)
    except Exception:
        pass

# ---------- App ----------
class DiffApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1280x800")
        self.minsize(1040, 680)

        # Fonts (after root)
        self.FONT_BASE = ctk.CTkFont(family="Segoe UI", size=12)
        self.FONT_SMALL = ctk.CTkFont(family="Segoe UI", size=11)
        self.FONT_MED = ctk.CTkFont(family="Segoe UI", size=13)
        self.FONT_H1 = ctk.CTkFont(family="Segoe UI", size=16, weight="bold")
        self.FONT_H2 = ctk.CTkFont(family="Segoe UI", size=14, weight="bold")
        self.FONT_TAG = ctk.CTkFont(family="Segoe UI", size=14, weight="bold")  # for meta tags

        self._profiles = self._safe_load_profiles()
        self._source_index: Optional[DatIndex] = None
        self._source_path: Optional[str] = None
        self._target_index: Optional[DatIndex] = None
        self._target_path: Optional[str] = None
        self._current_diff: Optional[DiffResult] = None

        # Sorting state
        self._sort_state: Dict[Tuple[ttk.Treeview, str], bool] = {}
        self._tree_headings: Dict[ttk.Treeview, Dict[str, str]] = {}

        # UI prefs
        self._ui_prefs: Dict[str, List[str]] = load_ui_prefs()

        self._build_ui()
        self._init_tree_styles()
        self._style_treeviews()

        # Apply initial visible columns after trees exist
        self._apply_visible_columns("roms_added",  self.roms_added_tree,  self.ROMS_COLS)
        self._apply_visible_columns("roms_removed", self.roms_removed_tree, self.ROMS_COLS)
        self._apply_visible_columns("roms_changed", self.roms_changed_tree, self.ROMS_CHANGED_COLS)

    # ---------- Build UI ----------
    def _build_ui(self):
        # Column constants
        self.ROMS_COLS = ["Game", "ROM", "Size", "CRC", "MD5", "SHA1"]
        self.ROMS_CHANGED_COLS = ["Game", "ROM", "Old Size", "New Size", "Old CRC", "New CRC", "Old MD5", "New MD5", "Old SHA1", "New SHA1"]

        # Top bar
        top = ctk.CTkFrame(self, corner_radius=0)
        top.pack(side="top", fill="x")

        left = ctk.CTkFrame(top, fg_color="transparent")
        left.pack(side="left", padx=8, pady=8)

        ctk.CTkLabel(left, text="DAT Diff", font=self.FONT_H1).pack(side="top", anchor="w")

        controls = ctk.CTkFrame(left, fg_color="transparent")
        controls.pack(side="top", anchor="w", pady=(6, 0))

        self.profile_var = tk.StringVar()
        self.profile_combo = ctk.CTkComboBox(
            controls,
            variable=self.profile_var,
            values=sorted(list(self._profiles.keys())),
            width=260,
            command=self.on_profile_selected,
            font=self.FONT_BASE,
        )
        self.profile_combo.set("Select source profile…")
        self.profile_combo.pack(side="left", padx=(0, 8))

        # NEW: Quick load (no profile created)
        self.btn_quick_load = ctk.CTkButton(
            controls, text="Quick Load Source DAT",
            command=self.quick_load_source_dat, font=self.FONT_MED, height=36)
        self.btn_quick_load.pack(side="left", padx=6)

        self.btn_load_target = ctk.CTkButton(
            controls, text="Compare Another DAT…",
            command=self.load_target_dat, font=self.FONT_MED, height=36)
        self.btn_load_target.pack(side="left", padx=6)

        # Manage Profiles button
        self.btn_manage_profiles = ctk.CTkButton(
            controls, text="Manage Source Profiles…",
            command=self._open_profile_manager, font=self.FONT_MED, height=36)
        self.btn_manage_profiles.pack(side="left", padx=6)

        right = ctk.CTkFrame(top, fg_color="transparent")
        right.pack(side="right", padx=8, pady=8)

        ctk.CTkLabel(right, text="Appearance:", font=self.FONT_SMALL).pack(side="left", padx=(0, 6))
        self.appearance_var = tk.StringVar(value="Dark")
        self.appearance_menu = ctk.CTkOptionMenu(
            right, values=["Dark", "Light", "System"], variable=self.appearance_var,
            command=self._on_appearance_changed, font=self.FONT_BASE, width=110)
        self.appearance_menu.pack(side="left", padx=(0, 12))

        ttk.Separator(self, orient="horizontal").pack(fill="x")

        # Tabs
        self.tabs = ctk.CTkTabview(self)
        self.tabs.pack(expand=True, fill="both", padx=10, pady=10)

        self.tab_summary = self.tabs.add("Summary")
        self.tab_games = self.tabs.add("Games")
        self.tab_roms = self.tabs.add("ROMs")

        # --- Summary (structured, side-by-side) ---
        self.summary_root = ctk.CTkFrame(self.tab_summary)
        self.summary_root.pack(fill="both", expand=True, padx=8, pady=8)

        self.summary_meta = ctk.CTkFrame(self.summary_root)
        self.summary_meta.pack(fill="x")

        hdr = ctk.CTkFrame(self.summary_meta, fg_color="transparent")
        hdr.grid_columnconfigure(0, weight=1)
        hdr.grid_columnconfigure(1, weight=1)
        hdr.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(hdr, text="Source Metadata", font=self.FONT_H2).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(hdr, text="Target Metadata", font=self.FONT_H2).grid(row=0, column=1, sticky="w")

        self.summary_meta_grid = ctk.CTkFrame(self.summary_meta)
        self.summary_meta_grid.grid_columnconfigure(0, weight=1)
        self.summary_meta_grid.grid_columnconfigure(1, weight=1)
        self.summary_meta_grid.pack(fill="x")

        ttk.Separator(self.summary_root, orient="horizontal").pack(fill="x", pady=8)

        self.summary_diff = ctk.CTkFrame(self.summary_root)
        self.summary_diff.pack(fill="x")
        ctk.CTkLabel(self.summary_diff, text="Diff Summary", font=self.FONT_H2).pack(anchor="w")
        self.summary_diff_body = ctk.CTkFrame(self.summary_diff)
        self.summary_diff_body.pack(fill="x", pady=(4, 0))

        # --- Games tab ---
        games_frame = ctk.CTkFrame(self.tab_games)
        games_frame.pack(fill="both", expand=True, padx=8, pady=8)

        games_frame.grid_columnconfigure(0, weight=1)
        games_frame.grid_columnconfigure(1, weight=1)
        games_frame.grid_rowconfigure(1, weight=1)

        # Trees first (so headers can reference them)
        self.games_added_frame, self.games_added_tree = self._make_tree(games_frame, ["Game"], stretch_col=0, numeric_cols=set())
        self.games_removed_frame, self.games_removed_tree = self._make_tree(games_frame, ["Game"], stretch_col=0, numeric_cols=set())

        self.games_added_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 6), pady=6)
        self.games_removed_frame.grid(row=1, column=1, sticky="nsew", padx=(6, 0), pady=6)

        # Headers with actions (Copy/Export) — no Columns for Games
        self._make_header_with_actions(
            games_frame, "Games Added", 0, 0,
            tree=self.games_added_tree, all_cols=["Game"], on_columns_click=None
        )
        self._make_header_with_actions(
            games_frame, "Games Removed", 0, 1,
            tree=self.games_removed_tree, all_cols=["Game"], on_columns_click=None
        )

        # --- ROMs tab ---
        roms_frame = ctk.CTkFrame(self.tab_roms)
        roms_frame.pack(fill="both", expand=True, padx=8, pady=8)

        roms_frame.grid_columnconfigure(0, weight=1)
        roms_frame.grid_columnconfigure(1, weight=1)
        roms_frame.grid_columnconfigure(2, weight=2)
        roms_frame.grid_rowconfigure(1, weight=1)

        # Trees first
        self.roms_added_frame, self.roms_added_tree = self._make_tree(roms_frame, self.ROMS_COLS, stretch_col=1, numeric_cols={2})
        self.roms_removed_frame, self.roms_removed_tree = self._make_tree(roms_frame, self.ROMS_COLS, stretch_col=1, numeric_cols={2})
        self.roms_changed_frame, self.roms_changed_tree = self._make_tree(roms_frame, self.ROMS_CHANGED_COLS, stretch_col=1, numeric_cols={2, 3})

        self.roms_added_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 6), pady=6)
        self.roms_removed_frame.grid(row=1, column=1, sticky="nsew", padx=6, pady=6)
        self.roms_changed_frame.grid(row=1, column=2, sticky="nsew", padx=(6, 0), pady=6)

        # Headers with Columns + Copy/Export
        self._make_header_with_actions(
            roms_frame, "ROMs Added", 0, 0,
            tree=self.roms_added_tree, all_cols=self.ROMS_COLS,
            on_columns_click=lambda: self._open_columns_dialog("roms_added", self.roms_added_tree, self.ROMS_COLS, UI_DEFAULTS["roms_added"])
        )
        self._make_header_with_actions(
            roms_frame, "ROMs Removed", 0, 1,
            tree=self.roms_removed_tree, all_cols=self.ROMS_COLS,
            on_columns_click=lambda: self._open_columns_dialog("roms_removed", self.roms_removed_tree, self.ROMS_COLS, UI_DEFAULTS["roms_removed"])
        )
        self._make_header_with_actions(
            roms_frame, "ROMs Changed", 0, 2,
            tree=self.roms_changed_tree, all_cols=self.ROMS_CHANGED_COLS,
            on_columns_click=lambda: self._open_columns_dialog("roms_changed", self.roms_changed_tree, self.ROMS_CHANGED_COLS, UI_DEFAULTS["roms_changed"])
        )

        # Bottom status bar
        status_frame = ctk.CTkFrame(self, height=28, corner_radius=0)
        status_frame.pack(side="bottom", fill="x")

        self.status_var = tk.StringVar(value="Ready.")
        ctk.CTkLabel(
            status_frame,
            textvariable=self.status_var,
            anchor="w",
            font=self.FONT_SMALL,
            padx=8
        ).pack(side="left", fill="x")
        self._set_status("Select or create a source profile, then ‘Compare Another DAT…’")



    # ---------- Theming & Styles ----------
    def _init_tree_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        # Theme-agnostic structural bits only; colors are handled in _style_treeviews()
        style.configure("Treeview", rowheight=24, borderwidth=0, highlightthickness=0)
        style.configure("Treeview.Heading", font=("Segoe UI", 13, "bold"))

    # ---------- Summary rendering ----------
    def _human_bytes(self, n: int) -> str:
        """Pretty size with binary units (B, KB, MB, GB, TB), keeping sign."""
        if n is None:
            return "-"
        sign = "-" if n < 0 else ""
        v = float(abs(n))
        units = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while v >= 1024 and i < len(units) - 1:
            v /= 1024.0
            i += 1
        s = f"{v:.1f}" if v < 10 and i > 0 else f"{v:.0f}"
        return f"{sign}{s} {units[i]}"

    def _compute_size_stats(self, diff: Optional["DiffResult"]) -> dict:
        if not diff:
            return {
                "added_bytes": None,
                "removed_bytes": None,
                "changed_delta": None,
                "total_delta": None,
            }

        def iter_entries(x):
            if x is None:
                return []
            try:
                return x.values() if isinstance(x, dict) else list(x)
            except Exception:
                return []

        def get_size(item):
            """Return an int size if present; for (old, new) pairs prefer the new side."""
            try:
                s = getattr(item, "size", None)
                if s is not None:
                    return int(s)
            except Exception:
                pass
            if isinstance(item, (tuple, list)) and item:
                cand = item[-1]  # new side
                try:
                    s2 = getattr(cand, "size", None)
                    if s2 is not None:
                        return int(s2)
                except Exception:
                    pass
            return None

        def safe_sum(x):
            total = 0
            has_any = False
            for it in iter_entries(x):
                s = get_size(it)
                if s is not None:
                    total += s
                    has_any = True
            return total if has_any else None

        added   = safe_sum(diff.roms_added)     # list or dict OK
        removed = safe_sum(diff.roms_removed)   # list or dict OK
        changed = safe_sum(diff.roms_changed)   # list of entries or (old,new) pairs

        changed_delta = changed  # preserves your current semantics

        if all(v is None for v in (added, removed, changed_delta)):
            total = None
        else:
            total = (added or 0) - (removed or 0) + (changed_delta or 0)

        return {
            "added_bytes": added,
            "removed_bytes": removed,
            "changed_delta": changed_delta,
            "total_delta": total,
        }

    def _render_summary(self, diff: Optional["DiffResult"] = None):
        # Clear existing content
        for w in self.summary_meta_grid.winfo_children():
            w.destroy()
        for w in self.summary_diff_body.winfo_children():
            w.destroy()

        # Two equal columns in the grid that holds Source/Target stacks
        self.summary_meta_grid.grid_columnconfigure(0, weight=1, uniform="meta")
        self.summary_meta_grid.grid_columnconfigure(1, weight=1, uniform="meta")

        # Compute a wrap length that fits within one column
        def _wrap_len():
            try:
                self.update_idletasks()
                w = self.summary_meta_grid.winfo_width()
                return max(320, (w // 2) - 120) if w else 420  # leave room for padding + badge
            except Exception:
                return 420
        wraplength = _wrap_len()

        # ---- Gather metadata ----
        src_meta = self._source_index.meta if self._source_index else {}
        tgt_meta = self._target_index.meta if self._target_index else {}

        preferred = ["name", "description", "version", "date", "author", "homepage", "url", "comment"]
        keyset = set(src_meta.keys()) | set(tgt_meta.keys())
        ordered_keys = [k for k in preferred if k in keyset] + sorted(k for k in keyset if k not in preferred)

        row = 0

        # ---- Helpers: single-row (grid) layouts with top alignment ----
        def add_source_row(k: str, val: str):
            rf = ctk.CTkFrame(self.summary_meta_grid, fg_color="transparent")
            rf.grid(row=row, column=0, sticky="ew", padx=6, pady=0)
            # Tag (col 0), Value (col 1)
            rf.grid_columnconfigure(0, minsize=120)  # fixed tag width for neat alignment
            rf.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(rf, text=f"{k.capitalize()}:", font=self.FONT_TAG, anchor="w")\
               .grid(row=0, column=0, sticky="nw", padx=(0, 6))
            ctk.CTkLabel(rf, text=(val or "—"), font=self.FONT_BASE,
                         wraplength=wraplength, justify="left", anchor="w")\
               .grid(row=0, column=1, sticky="nw")

        def add_target_row(k: str, val: str, same: bool):
            rf = ctk.CTkFrame(self.summary_meta_grid, fg_color="transparent")
            rf.grid(row=row, column=1, sticky="ew", padx=6, pady=0)
            # Tag (col 0), Value (col 1), Badge (col 2)
            rf.grid_columnconfigure(0, minsize=120)
            rf.grid_columnconfigure(1, weight=1)   # value grows
            rf.grid_columnconfigure(2, minsize=1)

            ctk.CTkLabel(rf, text=f"{k.capitalize()}:", font=self.FONT_TAG, anchor="w")\
               .grid(row=0, column=0, sticky="nw", padx=(0, 6))
            ctk.CTkLabel(rf, text=(val or "—"), font=self.FONT_BASE,
                         wraplength=wraplength, justify="left", anchor="w")\
               .grid(row=0, column=1, sticky="nw")
            badge_text  = "✓ same" if same else "≠ changed"
            badge_color = "#27ae60" if same else "#f39c12"
            ctk.CTkLabel(rf, text=badge_text, font=self.FONT_SMALL, text_color=badge_color, anchor="e")\
               .grid(row=0, column=2, sticky="ne", padx=(6, 0))

        # ---- Render header metadata as compact rows ----
        for k in ordered_keys:
            s = src_meta.get(k, "")
            t = tgt_meta.get(k, "")
            same = (s.strip() == t.strip()) if (s and t) else (s == t)
            add_source_row(k, s)
            add_target_row(k, t, same)
            row += 1

        # ---- Computed stats (Number of games / ROMs / Total size) ----
        src_stats = self._index_stats(self._source_index)
        tgt_stats = self._index_stats(self._target_index)

        src_games, src_roms, src_bytes = src_stats["games"], src_stats["roms"], src_stats["bytes"]
        tgt_games, tgt_roms, tgt_bytes = tgt_stats["games"], tgt_stats["roms"], tgt_stats["bytes"]


        def _fmt_int(n: int) -> str: return f"{n:,}"
        def _fmt_bytes(n: Optional[int]) -> str:
            if n is None:
                return "Unknown"
            return f"{self._human_bytes(n)} ({n:,} B)"

        stats = [
            ("Number of games",     _fmt_int(src_games),   _fmt_int(tgt_games)),
            ("Number of rom files", _fmt_int(src_roms),    _fmt_int(tgt_roms)),
            ("Total size",          _fmt_bytes(src_bytes), _fmt_bytes(tgt_bytes)),
        ]

        for label, s_val, t_val in stats:
            same = (s_val == t_val)
            add_source_row(label, s_val)
            add_target_row(label, t_val, same)
            row += 1

        # ---- Diff Summary (counts + byte deltas) ----
        ga = len(diff.games_added)   if diff else 0
        gr = len(diff.games_removed) if diff else 0
        ra = len(diff.roms_added)    if diff else 0
        rr = len(diff.roms_removed)  if diff else 0
        rc = len(diff.roms_changed)  if diff else 0

        # Compute byte deltas with None-awareness (use the class helper)
        sz = self._compute_size_stats(diff)

        def _fmt_diff_bytes(n: Optional[int]) -> str:
            if n is None:
                return "Unknown"
            return f"{self._human_bytes(n)} ({n:,} B)"

        add_h = _fmt_diff_bytes(sz["added_bytes"])
        rem_h = _fmt_diff_bytes(sz["removed_bytes"])
        chg_h = _fmt_diff_bytes(sz["changed_delta"])
        tot_h = _fmt_diff_bytes(sz["total_delta"])

        # Only color green/red if numeric; otherwise neutral
        if sz["total_delta"] is None:
            tot_color = "#a0a0a0"
        else:
            tot_color = "#27ae60" if sz["total_delta"] >= 0 else "#e74c3c"

        line1 = ctk.CTkFrame(self.summary_diff_body, fg_color="transparent")
        line1.pack(fill="x", pady=0)
        ctk.CTkLabel(line1, text=f"Games added: {ga}",   font=self.FONT_BASE).pack(side="left", padx=(0, 16))
        ctk.CTkLabel(line1, text=f"Games removed: {gr}", font=self.FONT_BASE).pack(side="left", padx=(0, 16))
        ctk.CTkLabel(line1, text=f"ROMs added: {ra}",    font=self.FONT_BASE).pack(side="left", padx=(0, 16))
        ctk.CTkLabel(line1, text=f"ROMs removed: {rr}",  font=self.FONT_BASE).pack(side="left", padx=(0, 16))
        ctk.CTkLabel(line1, text=f"ROMs changed: {rc}",  font=self.FONT_BASE).pack(side="left")

        line2 = ctk.CTkFrame(self.summary_diff_body, fg_color="transparent")
        line2.pack(fill="x", pady=0)
        ctk.CTkLabel(line2, text=f"Bytes added: {add_h}",     font=self.FONT_BASE).pack(side="left", padx=(0, 16))
        ctk.CTkLabel(line2, text=f"Bytes removed: {rem_h}",   font=self.FONT_BASE).pack(side="left", padx=(0, 16))
        ctk.CTkLabel(line2, text=f"Changed Δ: {chg_h}",       font=self.FONT_BASE).pack(side="left", padx=(0, 16))
        ctk.CTkLabel(line2, text=f"Total Δ: {tot_h}",         font=self.FONT_BASE, text_color=tot_color).pack(side="left")

        # Optional notices for empty sets
        src_empty = not (self._source_index and getattr(self._source_index, "games", None))
        tgt_empty = not (self._target_index and getattr(self._target_index, "games", None))
        if src_empty:
            ctk.CTkLabel(self.summary_diff_body, text="Note: Source DAT contains no games/ROMs.",
                         font=self.FONT_SMALL, text_color="#f39c12").pack(anchor="w")
        if tgt_empty:
            ctk.CTkLabel(self.summary_diff_body, text="Note: Target DAT contains no games/ROMs.",
                         font=self.FONT_SMALL, text_color="#f39c12").pack(anchor="w")


    # ---------- Column visibility ----------
    def _apply_visible_columns(self, key: str, tree: ttk.Treeview, all_cols: List[str]):
        visible = self._ui_prefs.get(key, all_cols)
        vis_set = set(visible)
        display_cols = [c for c in all_cols if c in vis_set] or [all_cols[0]]
        tree.configure(displaycolumns=display_cols)

    def _center_toplevel(self, win, parent=None):
        parent = parent or self
        parent.update_idletasks()
        win.update_idletasks()
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        ww, wh = win.winfo_width(), win.winfo_height()
        x = px + max(0, (pw - ww) // 2)
        y = py + max(0, (ph - wh) // 2)
        win.geometry(f"+{x}+{y}")

    def _open_columns_dialog(self, key: str, tree: ttk.Treeview, all_cols: List[str], defaults: List[str]):
        dlg = ctk.CTkToplevel(self)
        dlg.title(f"Columns: {key.replace('_',' ').title()}")
        dlg.transient(self)
        dlg.grab_set()
        dlg.resizable(False, False)

        current_visible = set(self._ui_prefs.get(key, all_cols))

        ctk.CTkLabel(dlg, text="Show columns", font=self.FONT_MED).pack(padx=14, pady=(12, 6), anchor="w")
        body = ctk.CTkFrame(dlg)
        body.pack(padx=14, pady=6, fill="both", expand=True)

        vars_by_col: Dict[str, tk.BooleanVar] = {}
        for col in all_cols:
            var = tk.BooleanVar(value=(col in current_visible))
            vars_by_col[col] = var
            ctk.CTkCheckBox(body, text=col, variable=var, font=self.FONT_BASE).pack(anchor="w", padx=4, pady=3)

        btns = ctk.CTkFrame(dlg)
        btns.pack(padx=14, pady=(8, 12), fill="x")

        def apply_and_close(event=None):
            visible = [c for c in all_cols if vars_by_col[c].get()]
            if not visible:
                messagebox.showwarning("Choose at least one", "You must have at least one column visible.")
                return
            self._ui_prefs[key] = visible
            save_ui_prefs(self._ui_prefs)
            self._apply_visible_columns(key, tree, all_cols)
            dlg.destroy()

        ctk.CTkButton(btns, text="Cancel", command=dlg.destroy, font=self.FONT_MED, width=88).pack(side="right", padx=(8, 0))
        ok_btn = ctk.CTkButton(btns, text="OK", command=apply_and_close, font=self.FONT_MED, width=88)
        ok_btn.pack(side="right")

        dlg.bind("<Return>", apply_and_close)
        dlg.bind("<Escape>", lambda e: dlg.destroy())
        ok_btn.focus_set()
        dlg.update_idletasks()
        self._center_toplevel(dlg)
        dlg.wait_window()
    
    def _list_dat_like_in_zip(self, zip_path: str) -> List[str]:
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                return [n for n in zf.namelist()
                        if not n.endswith("/") and n.lower().endswith((".dat", ".xml"))]
        except Exception as e:
            messagebox.showerror("ZIP error", f"Failed to open ZIP:\n{zip_path}\n\n{e}")
            return []

    def _read_zip_member_bytes(self, zip_path: str, member: str) -> Optional[bytes]:
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                with zf.open(member, "r") as f:
                    return f.read()
        except Exception as e:
            messagebox.showerror("ZIP error", f"Failed to read from ZIP:\n{zip_path}\n\n{e}")
            return None

    def _choose_files_in_zip(self, parent, zip_path: str, multi: bool) -> Optional[List[str]]:
        """Return list of chosen members (one for single-select). None = cancel."""
        members = self._list_dat_like_in_zip(zip_path)
        if not members:
            messagebox.showinfo("No DAT/XML", f"No .dat/.xml files found in:\n{zip_path}")
            return None
        if len(members) == 1:
            return [members[0]]  # nothing to choose

        dlg = ctk.CTkToplevel(parent)
        dlg.title(("Select files in ZIP" if multi else "Select a file in ZIP"))
        dlg.transient(parent)
        dlg.grab_set()
        dlg.resizable(True, True)

        ctk.CTkLabel(dlg, text=os.path.basename(zip_path), font=self.FONT_H2).pack(anchor="w", padx=12, pady=(12, 6))

        # Scrollable list
        list_frame = ctk.CTkScrollableFrame(dlg, width=580, height=320)
        list_frame.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        chosen: List[str] = []
        if multi:
            vars_by_name: Dict[str, tk.BooleanVar] = {}
            for name in members:
                var = tk.BooleanVar(value=False)
                vars_by_name[name] = var
                ctk.CTkCheckBox(list_frame, text=name, variable=var, font=self.FONT_BASE).pack(anchor="w", padx=6, pady=3)
        else:
            sel = tk.StringVar(value="")
            for name in members:
                ctk.CTkRadioButton(list_frame, text=name, variable=sel, value=name, font=self.FONT_BASE).pack(anchor="w", padx=6, pady=3)

        # Buttons row
        btns = ctk.CTkFrame(dlg)
        btns.pack(fill="x", padx=12, pady=(0, 12))

        def on_ok(event=None):
            nonlocal chosen
            if multi:
                chosen = [n for n in members if vars_by_name[n].get()]
                if not chosen:
                    messagebox.showinfo("Select files", "Please select at least one file.")
                    return
            else:
                if not sel.get():
                    messagebox.showinfo("Select a file", "Please select one file.")
                    return
                chosen = [sel.get()]
            dlg.destroy()

        if multi:
            # Select All / None
            ctk.CTkButton(btns, text="Select All", width=0, height=28, font=self.FONT_SMALL,
                          command=lambda: [v.set(True) for v in vars_by_name.values()]).pack(side="left")
            ctk.CTkButton(btns, text="Deselect All", width=0, height=28, font=self.FONT_SMALL,
                          command=lambda: [v.set(False) for v in vars_by_name.values()]).pack(side="left", padx=(8,0))

        ctk.CTkButton(btns, text="Cancel", width=92, height=28, font=self.FONT_MED,
                      command=dlg.destroy).pack(side="right", padx=(8,0))
        ok_btn = ctk.CTkButton(btns, text="OK", width=92, height=28, font=self.FONT_MED,
                               command=on_ok)
        ok_btn.pack(side="right")

        dlg.bind("<Return>", on_ok)
        dlg.bind("<Escape>", lambda e: dlg.destroy())
        dlg.update_idletasks()
        self._center_toplevel(dlg, parent)
        ok_btn.focus_set()
        dlg.wait_window()
        return chosen if chosen else None
        
    
    # ---------- Header builder with actions ----------
    def _make_header_with_actions(self, parent, text: str, row: int, col: int,
                                  tree: ttk.Treeview, all_cols: List[str],
                                  on_columns_click=None):
        """Header row with title + optional Columns… + Copy + Export buttons."""
        cell = ctk.CTkFrame(parent, fg_color="transparent")
        cell.grid(row=row, column=col, sticky="w", padx=4, pady=(4, 0))

        ctk.CTkLabel(cell, text=text, font=self.FONT_H2).pack(side="left")

        # Optional Columns… (ROMs tables)
        if on_columns_click is not None:
            ctk.CTkButton(cell, text="Columns", width=0, height=24,
                          font=self.FONT_SMALL, command=on_columns_click).pack(side="left", padx=(6, 0))

        # Copy to Clipboard
        ctk.CTkButton(cell, text="Copy to Clipboard", width=0, height=24, font=self.FONT_SMALL,
                      command=lambda: self._copy_tree_to_clipboard(tree, all_cols)).pack(side="left", padx=(6, 0))

        # Export to CSV
        default_name = text.lower().replace(" ", "_")
        ctk.CTkButton(cell, text="Export to CSV", width=0, height=24, font=self.FONT_SMALL,
                      command=lambda: self._export_tree_to_csv(tree, all_cols, default_name)).pack(side="left", padx=(6, 0))

    # ---------- Sorting ----------
    def _register_tree_headings(self, tree: ttk.Treeview, columns: List[str]):
        self._tree_headings[tree] = {col: tree.heading(col, option="text") for col in columns}

    def _enable_tree_sort(self, tree: ttk.Treeview, columns: List[str], numeric_cols: Set[int]):
        for idx, col in enumerate(columns):
            def _cmd(c=col, i=idx):
                self._sort_tree(tree, columns, c, i, numeric_cols)
            tree.heading(col, command=_cmd)

    def _update_heading_arrows(self, tree: ttk.Treeview, columns: List[str], sort_col: str, ascending: bool):
        original = self._tree_headings.get(tree, {})
        for col in columns:
            base = original.get(col, col)
            tree.heading(col, text=base)
        arrow = " ▲" if ascending else " ▼"
        base = original.get(sort_col, sort_col)
        tree.heading(sort_col, text=base + arrow)

    def _sort_tree(self, tree: ttk.Treeview, columns: List[str], col: str, col_index: int, numeric_cols: Set[int]):
        key = (tree, col)
        ascending = not self._sort_state.get(key, True)
        self._sort_state[key] = ascending

        items = list(tree.get_children(""))
        non_none_entries = []
        none_entries = []
        for original_pos, iid in enumerate(items):
            vals = tree.item(iid, "values")
            cell = vals[col_index] if col_index < len(vals) else ""
            if col_index in numeric_cols:
                try:
                    v = int(cell)
                    non_none_entries.append((v, original_pos, iid))
                except Exception:
                    none_entries.append((original_pos, iid))
            else:
                v = (cell or "").lower()
                if v == "":
                    none_entries.append((original_pos, iid))
                else:
                    non_none_entries.append((v, original_pos, iid))

        non_none_entries.sort(key=lambda t: (t[0], t[1]), reverse=not ascending)
        new_order = [iid for _, _, iid in non_none_entries] + [iid for _, iid in none_entries]
        for iid in new_order:
            tree.move(iid, "", "end")

        self._zebra_fill(tree)
        self._update_heading_arrows(tree, columns, col, ascending)

    # ---------- Copy/Export helpers ----------
    def _index_stats(self, idx: Optional["DatIndex"]) -> Dict[str, int]:
        if not idx:
            return {"games": 0, "roms": 0, "bytes": None}
        total_bytes = 0
        has_any = False
        for r in idx.by_game_rom.values():
            if r.size is not None:
                try:
                    total_bytes += int(r.size)
                    has_any = True
                except Exception:
                    pass
        return {
            "games": len(idx.games),
            "roms": len(idx.by_game_rom),
            "bytes": (total_bytes if has_any else None),
        }
   
    def _tree_get_visible_columns(self, tree: ttk.Treeview, all_cols: List[str]) -> List[str]:
        """Return the columns currently visible for a tree, preserving order."""
        dc = tree.cget("displaycolumns")
        # If nothing set or Tk is indicating "all" columns, return all
        if not dc:
            return list(all_cols)
        # dc might be "#all" (str) or ("#all",) (tuple) depending on platform/Tk
        if (isinstance(dc, str) and dc == "#all") or (isinstance(dc, (list, tuple)) and len(dc) == 1 and dc[0] == "#all"):
            return list(all_cols)
        # Convert any Tk sequence to a Python list of strings
        try:
            seq = list(dc)
        except Exception:
            return list(all_cols)
        # Filter out any stray sentinel values just in case
        return [c for c in seq if c in all_cols]


    def _iter_tree_rows(self, tree: ttk.Treeview):
        """Yield each row's tuple(values)."""
        for iid in tree.get_children(""):
            yield tree.item(iid, "values")
       
    def _all_trees(self):
        """Return all Treeviews we use (ignore ones not built yet)."""
        return [
            getattr(self, "games_added_tree", None),
            getattr(self, "games_removed_tree", None),
            getattr(self, "roms_added_tree", None),
            getattr(self, "roms_removed_tree", None),
            getattr(self, "roms_changed_tree", None),
            getattr(self, "pm_tree", None),  # profile manager tree
        ]

    def _restyle_tree_tags(self, mode: str):
        """Update zebra-row backgrounds to match the theme."""
        if mode == "Light":
            bg = "#FFFFFF"
            alt = "#F2F2F2"  # subtle light gray
        else:
            bg  = "#1E1E1E"
            alt = "#252526"

        for t in self._all_trees():
            if t is None:
                continue
            # overwrite previous tag colors
            try:
                t.tag_configure("even", background=bg)
                t.tag_configure("odd",  background=alt)
            except Exception:
                pass


    def _copy_tree_to_clipboard(self, tree: ttk.Treeview, all_cols: List[str]):
        cols = [c for c in self._tree_get_visible_columns(tree, all_cols) if c in all_cols]
        lines = ["\t".join(cols)]
        idx_map = {c: all_cols.index(c) for c in cols}
        count = 0
        for vals in self._iter_tree_rows(tree):
            row = []
            for c in cols:
                i = idx_map[c]
                v = vals[i] if i < len(vals) else ""
                row.append("" if v is None else str(v))
            lines.append("\t".join(row))
            count += 1
        txt = "\n".join(lines)
        try:
            self.clipboard_clear()
            self.clipboard_append(txt)
            self.update()  # persist
            self._set_status(f"Copied {count} row(s) to clipboard.")
        except Exception as e:
            self._error(f"Clipboard failed: {e}")

    def _export_tree_to_csv(self, tree: ttk.Treeview, all_cols: List[str], default_basename: str):
        cols = [c for c in self._tree_get_visible_columns(tree, all_cols) if c in all_cols]
        path = filedialog.asksaveasfilename(
            title="Export to CSV",
            defaultextension=".csv",
            initialfile=f"{default_basename}.csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not path:
            return

        import csv
        idx_map = {c: all_cols.index(c) for c in cols}
        count = 0
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f)
                w.writerow(cols)
                for vals in self._iter_tree_rows(tree):
                    row = []
                    for c in cols:
                        i = idx_map[c]
                        v = vals[i] if i < len(vals) else ""
                        row.append("" if v is None else v)
                    w.writerow(row)
                    count += 1
            self._set_status(f"Exported {count} row(s) to {os.path.basename(path)}")
        except Exception as e:
            self._error(f"Export failed: {e}")

    # ---------- Tree factory ----------
    def _style_treeviews(self):
        """Apply base Treeview colors for the current appearance and retag zebra rows."""
        style = ttk.Style()
        mode = ctk.get_appearance_mode()  # "Light" or "Dark"

        if mode == "Light":
            # do NOT force foreground here; we keep your tag colors
            style.configure("Treeview",
                            background="#FFFFFF",
                            fieldbackground="#FFFFFF",
                            foreground="#000000")
            style.map("Treeview",
                      background=[("selected", "#0078D7")],
                      foreground=[("selected", "#FFFFFF")])

            # Column header look (optional but nicer)
            style.configure("Treeview.Heading",
                            background="#E6E6E6",
                            foreground="#000000")
        else:
            style.configure("Treeview",
                            background="#1E1E1E",
                            fieldbackground="#1E1E1E",
                            foreground="#E6E6E6")
            style.map("Treeview",
                      background=[("selected", "#094771")],
                      foreground=[("selected", "#FFFFFF")])
            style.configure("Treeview.Heading",
                            background="#2A2A2A",
                            foreground="#E6E6E6")

        # Update zebra row tag backgrounds
        self._restyle_tree_tags(mode)

        # Reapply zebra tagging so newly visible rows pick up the right bg
        for t in self._all_trees():
            if t is None:
                continue
            try:
                self._zebra_fill(t)
            except Exception:
                pass

    
    
    def _make_tree(self, parent, columns: List[str], stretch_col: int = 0, numeric_cols: Set[int] = set()) -> Tuple[ctk.CTkFrame, ttk.Treeview]:
        if numeric_cols is None:
            numeric_cols = set()
        frame = ctk.CTkFrame(parent)
        tree = ttk.Treeview(frame, columns=columns, show="headings", height=8)
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        for i, col in enumerate(columns):
            width = 150 if i != stretch_col else 260
            tree.heading(col, text=col)
            tree.column(col, width=width, anchor="w", stretch=(i == stretch_col))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        try:
            tree.tag_configure("added", foreground=COLOR_ADDED)
            tree.tag_configure("removed", foreground=COLOR_REMOVED)
            tree.tag_configure("changed", foreground=COLOR_CHANGED)
            tree.tag_configure("odd", background=COLOR_BG_ALT)
            tree.tag_configure("even", background=COLOR_BG)
        except Exception:
            pass

        self._register_tree_headings(tree, columns)
        self._enable_tree_sort(tree, columns, numeric_cols)
        return frame, tree

    # ---------- Fillers ----------
    def _zebra_fill(self, tree: ttk.Treeview):
        for i, iid in enumerate(tree.get_children()):
            existing = list(tree.item(iid, "tags"))
            existing = [t for t in existing if t not in ("odd", "even")]
            zebra = "odd" if i % 2 else "even"
            tree.item(iid, tags=tuple(existing + [zebra]))

    def _fill_games(self, diff: DiffResult):
        self._clear_tree(self.games_added_tree)
        self._clear_tree(self.games_removed_tree)
        for g in diff.games_added:
            self.games_added_tree.insert("", "end", values=(g,), tags=("added",))
        for g in diff.games_removed:
            self.games_removed_tree.insert("", "end", values=(g,), tags=("removed",))
        self._zebra_fill(self.games_added_tree)
        self._zebra_fill(self.games_removed_tree)

    def _fill_roms(self, diff: DiffResult):
        self._clear_tree(self.roms_added_tree)
        self._clear_tree(self.roms_removed_tree)
        self._clear_tree(self.roms_changed_tree)

        def cs_tuple_str(cs: Checksum):
            crc, md5, sha1 = cs
            return (crc or "-"), (md5 or "-"), (sha1 or "-")

        for r in diff.roms_added:
            crc, md5, sha1 = cs_tuple_str(r.checksums)
            self.roms_added_tree.insert("", "end", values=(r.game, r.rom, r.size or "-", crc, md5, sha1), tags=("added",))
        for r in diff.roms_removed:
            crc, md5, sha1 = cs_tuple_str(r.checksums)
            self.roms_removed_tree.insert("", "end", values=(r.game, r.rom, r.size or "-", crc, md5, sha1), tags=("removed",))
        for old, new in diff.roms_changed:
            o_crc, o_md5, o_sha1 = cs_tuple_str(old.checksums)
            n_crc, n_md5, n_sha1 = cs_tuple_str(new.checksums)
            self.roms_changed_tree.insert(
                "", "end",
                values=(old.game, old.rom,
                        old.size or "-", new.size or "-",
                        o_crc, n_crc, o_md5, n_md5, o_sha1, n_sha1),
                tags=("changed",)
            )
        self._zebra_fill(self.roms_added_tree)
        self._zebra_fill(self.roms_removed_tree)
        self._zebra_fill(self.roms_changed_tree)

    # ---------- Profile Manager ----------
    def _unique_profile_name(self, base: str) -> str:
        name = base
        n = 2
        existing = set(self._profiles.keys())
        while name in existing:
            name = f"{base} ({n})"
            n += 1
        return name

    def _open_profile_manager(self):
        dlg = ctk.CTkToplevel(self)
        dlg.title("Profile Manager")
        dlg.transient(self)
        dlg.grab_set()
        dlg.geometry("860x420")
        dlg.resizable(True, True)

        ctk.CTkLabel(dlg, text="Profiles", font=self.FONT_H2).pack(anchor="w", padx=12, pady=(12, 6))

        body = ctk.CTkFrame(dlg)
        body.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        columns = ["Name", "Path"]
        self.pm_tree = ttk.Treeview(body, columns=columns, show="headings", height=10)
        for col in columns:
            self.pm_tree.heading(col, text=col)
            self.pm_tree.column(col, width=(200 if col == "Name" else 600), anchor="w", stretch=True)

        vsb = ttk.Scrollbar(body, orient="vertical", command=self.pm_tree.yview)
        hsb = ttk.Scrollbar(body, orient="horizontal", command=self.pm_tree.xview)
        self.pm_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(0, weight=1)
        self.pm_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        btns = ctk.CTkFrame(dlg)
        btns.pack(fill="x", padx=12, pady=(0, 12))

        ctk.CTkButton(btns, text="Add…",      command=lambda: self._pm_add_single(dlg),  font=self.FONT_MED, width=110).pack(side="left")
        ctk.CTkButton(btns, text="Bulk Add…", command=lambda: self._pm_bulk_add(dlg),    font=self.FONT_MED, width=110).pack(side="left", padx=(8,0))
        ctk.CTkButton(btns, text="Rename…",   command=lambda: self._pm_rename_selected(dlg), font=self.FONT_MED, width=110).pack(side="left", padx=(16,0))
        ctk.CTkButton(btns, text="Change DAT…", command=lambda: self._pm_rebrowse_selected(dlg), font=self.FONT_MED, width=110).pack(side="left", padx=(8,0))
        ctk.CTkButton(btns, text="Delete",    command=self._pm_delete_selected, font=self.FONT_MED, width=110).pack(side="left", padx=(8,0))

        ctk.CTkButton(btns, text="Close", command=dlg.destroy, font=self.FONT_MED, width=110).pack(side="right")

        self._pm_refresh_list()
        dlg.after(50, lambda: self._center_toplevel(dlg))

    def _pm_refresh_list(self):
        """Refill the Profile Manager tree with Name + Path (and ZIP member if present)."""
        if not hasattr(self, "pm_tree"):
            return
        for iid in self.pm_tree.get_children():
            self.pm_tree.delete(iid)
        for name in sorted(self._profiles.keys(), key=str.lower):
            rec = self._profiles[name]
            path = rec.get("path", "")
            member = rec.get("zip_member")
            shown = f"{path} :: {member}" if member else path
            self.pm_tree.insert("", "end", iid=name, values=(name, shown))

    def _pm_add_single(self, parent):
        path = filedialog.askopenfilename(
            parent=parent, title="Select DAT/XML or ZIP",
            filetypes=[("DAT/XML/ZIP", "*.dat *.xml *.zip *.gz"), ("All files", "*.*")]
        )
        if not path:
            return

        zip_member = None
        if path.lower().endswith(".zip"):
            chosen = self._choose_files_in_zip(parent, path, multi=False)
            if not chosen:
                return
            zip_member = chosen[0]

        # Suggest a name from file (prefer inner member if from ZIP)
        base_for_name = os.path.splitext(os.path.basename(zip_member or path))[0]
        name = self._pm_prompt_text(parent, "Add Profile", "Profile Name:", default=base_for_name)
        if not name:
            return

        name = self._unique_profile_name(name.strip())
        rec = {"path": os.path.abspath(path)}
        if zip_member:
            rec["zip_member"] = zip_member

        self._profiles[name] = rec
        self._save_profiles_and_refresh()

    def _pm_bulk_add(self, parent):
        paths = filedialog.askopenfilenames(
            parent=parent, title="Select multiple DAT/XML/ZIP files",
            filetypes=[("DAT/XML/ZIP", "*.dat *.xml *.zip *.gz"), ("All files", "*.*")]
        )
        if not paths:
            return

        add_count = 0
        for p in paths:
            lp = p.lower()
            if lp.endswith(".zip"):
                choices = self._choose_files_in_zip(parent, p, multi=True)
                if not choices:
                    continue
                for member in choices:
                    base = os.path.splitext(os.path.basename(member))[0]
                    name = self._unique_profile_name(base)
                    self._profiles[name] = {"path": os.path.abspath(p), "zip_member": member}
                    add_count += 1
            else:
                base = os.path.splitext(os.path.basename(p))[0]
                name = self._unique_profile_name(base)
                self._profiles[name] = {"path": os.path.abspath(p)}
                add_count += 1

        if add_count:
            self._save_profiles_and_refresh()


    def _pm_selected_name(self) -> Optional[str]:
        sel = self.pm_tree.selection()
        if not sel:
            messagebox.showinfo("Select a profile", "Please select a profile first.")
            return None
        return sel[0]

    def _pm_rename_selected(self, parent):
        cur = self._pm_selected_name()
        if not cur:
            return
        new = self._pm_prompt_text(parent, "Rename Profile", "New name:", default=cur)
        if not new or new == cur:
            return
        new = self._unique_profile_name(new.strip())
        self._profiles[new] = self._profiles.pop(cur)
        self._save_profiles_and_refresh()
        vals = sorted(list(self._profiles.keys()))
        self.profile_combo.configure(values=vals)
        if self.profile_var.get() == cur:
            self.profile_var.set(new)

    def _pm_rebrowse_selected(self, parent):
        cur = self._pm_selected_name()
        if not cur:
            return
        path = filedialog.askopenfilename(
            parent=parent, title=f"Select DAT/XML for '{cur}'",
            filetypes=[("DAT/XML", "*.dat *.xml *.zip *.gz"), ("All files", "*.*")]
        )
        if not path:
            return
        self._profiles[cur]["path"] = os.path.abspath(path)
        self._save_profiles_and_refresh()

    def _pm_delete_selected(self):
        cur = self._pm_selected_name()
        if not cur:
            return
        if not messagebox.askyesno("Delete Profile", f"Delete profile '{cur}'?"):
            return
        self._profiles.pop(cur, None)
        self._save_profiles_and_refresh()
        vals = sorted(list(self._profiles.keys()))
        self.profile_combo.configure(values=vals)
        if self.profile_var.get() == cur:
            self.profile_var.set("Select source profile…")

    def _pm_prompt_text(self, parent, title: str, prompt: str, default: str = "") -> Optional[str]:
        dlg = ctk.CTkToplevel(parent)
        dlg.title(title)
        dlg.transient(parent)
        dlg.grab_set()
        dlg.resizable(False, False)

        ctk.CTkLabel(dlg, text=prompt, font=self.FONT_MED).pack(padx=12, pady=(12, 6), anchor="w")
        var = tk.StringVar(value=default)
        entry = ctk.CTkEntry(dlg, textvariable=var, width=360, font=self.FONT_BASE)
        entry.pack(padx=12, pady=6)
        entry.select_range(0, tk.END)
        entry.icursor(tk.END)

        row = ctk.CTkFrame(dlg); row.pack(fill="x", padx=12, pady=(8, 12))
        res = {"value": None}
        def ok(event=None):
            res["value"] = var.get().strip()
            dlg.destroy()
        ctk.CTkButton(row, text="Cancel", command=dlg.destroy, font=self.FONT_MED, width=92).pack(side="right", padx=(8,0))
        ok_btn = ctk.CTkButton(row, text="OK", command=ok, font=self.FONT_MED, width=92); ok_btn.pack(side="right")

        dlg.bind("<Return>", ok)
        dlg.bind("<Escape>", lambda e: dlg.destroy())
        dlg.after(10, entry.focus_set)
        dlg.update_idletasks()
        self._center_toplevel(dlg, parent)
        dlg.wait_window()
        return res["value"]

    def _save_profiles_and_refresh(self):
        try:
            with open(PROFILE_STORE, "w", encoding="utf-8") as f:
                json.dump(self._profiles, f, indent=2)
        except Exception:
            pass
        self._pm_refresh_list()
        self.profile_combo.configure(values=sorted(list(self._profiles.keys())))

    # ---------- Profile actions ----------
    def _safe_load_profiles(self) -> Dict[str, Dict[str, str]]:
        if not os.path.exists(PROFILE_STORE):
            return {}
        try:
            with open(PROFILE_STORE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        return {}

    def on_profile_selected(self, name: str):
        if not name or name == "Select source profile…":
            return
        rec = self._profiles.get(name)
        if not rec:
            return
        # Use record-aware loader (supports ZIP members)
        self._load_source_from_record(rec, profile_name=name)

    def _finish_create_profile(self, name: str, path: str, idx: DatIndex):
        rec = {"path": os.path.abspath(path), "id": hash_bytes(("".join(sorted(idx.games))).encode("utf-8"))}
        name = self._unique_profile_name(name.strip())
        self._profiles[name] = rec
        try:
            with open(PROFILE_STORE, "w", encoding="utf-8") as f:
                json.dump(self._profiles, f, indent=2)
        except Exception:
            pass
        self.profile_combo.configure(values=sorted(list(self._profiles.keys())))
        self.profile_var.set(name)

        self._source_index = idx
        self._source_path = path
        self._current_diff = None
        self._target_index = None
        self._target_path = None
        self._render_summary()
        self._clear_diff_views()
        self._set_status(f"Profile '{name}' loaded ({len(idx.games)} games, {len(idx.by_game_rom)} ROM entries).")

    # ----- Load source from selected profile path (async parse) -----
    def _load_source_from_path(self, path: str, profile_name: Optional[str]):
        """Asynchronously parse the selected source DAT and load it as the current source profile."""
        self._set_status("Parsing source DAT…")
        self._run_bg(
            func=parse_dat_file,
            args=(path,),
            on_done=lambda idx: self._finish_load_source(profile_name, path, idx),
            on_err=lambda e: self._error(f"Failed to parse source DAT: {e}")
        )

    def quick_load_source_dat(self):
        """
        Let the user pick a source DAT/XML (or ZIP with inner DAT/XML),
        parse it, and set it as the current Source WITHOUT creating a profile.
        """
        path = filedialog.askopenfilename(
            title="Select source DAT/XML (or ZIP)",
            filetypes=[("DAT/XML/ZIP", "*.dat *.xml *.zip *.gz"), ("All files", "*.*")]
        )
        if not path:
            return

        zip_member = None
        if path.lower().endswith(".zip"):
            # Reuse the single-select ZIP chooser from Profile Manager
            chosen = self._choose_files_in_zip(self, path, multi=False)
            if not chosen:
                return
            zip_member = chosen[0]

        # Compose a friendly label for status (don’t create a profile)
        friendly_name = os.path.basename(zip_member or path)
        quick_label = f"(quick) {friendly_name}"

        def parse_bytes_worker():
            if zip_member:
                data = self._read_zip_member_bytes(path, zip_member)
                if data is None:
                    raise RuntimeError(f"Failed reading ZIP member: {zip_member}")
                return parse_dat_xml_bytes(data)
            else:
                return parse_dat_file(path)

        self._set_status("Parsing source DAT…")
        self._run_bg(
            func=parse_bytes_worker,
            args=(),
            on_done=lambda idx: self._finish_load_source(quick_label, path, idx),
            on_err=lambda e: self._error(f"Failed to parse source DAT: {e}")
        )


    def _finish_load_source(self, profile_name: Optional[str], path: str, idx: DatIndex):
        """Finalize loading the source profile after parsing completes."""
        self._source_index = idx
        self._source_path = path
        self._current_diff = None
        self._target_index = None
        self._target_path = None
        self._render_summary()
        self._clear_diff_views()
        prof_label = profile_name or "(unsaved profile)"
        self._set_status(f"Source loaded: {prof_label}  ({len(idx.games)} games, {len(idx.by_game_rom)} ROM entries)")
    
    def _load_source_from_record(self, rec: Dict[str, str], profile_name: Optional[str]):
        """
        Load a source profile from a record that may point to a ZIP + inner member.
        Falls back to normal file parse if no 'zip_member' is present.
        """
        path = rec.get("path")
        member = rec.get("zip_member")
        if not (path and os.path.exists(path)):
            messagebox.showwarning(
                "Profile Not Found",
                f"The stored path for profile '{profile_name or ''}' no longer exists.\n\nPath: {path}"
            )
            return

        def parse_bytes_worker():
            # If this profile points inside a ZIP, read those bytes and parse XML directly.
            if member:
                data = self._read_zip_member_bytes(path, member)
                if data is None:
                    raise RuntimeError(f"Failed reading ZIP member: {member}")
                return parse_dat_xml_bytes(data)
            # Otherwise parse the DAT/XML/GZ normally from disk.
            return parse_dat_file(path)

        self._set_status("Parsing source DAT…")
        self._run_bg(
            func=parse_bytes_worker,
            args=(),
            on_done=lambda idx: self._finish_load_source(profile_name, path, idx),
            on_err=lambda e: self._error(f"Failed to parse source DAT: {e}")
        )


    def load_target_dat(self):
        """Pick a target DAT/XML (or an inner file inside a ZIP), parse it, then compute the diff."""
        if not self._source_index:
            messagebox.showinfo("No Source", "Select or quick-load a source DAT first.")
            return

        path = filedialog.askopenfilename(
            title="Select target DAT/XML (or ZIP) to compare",
            filetypes=[("DAT/XML/ZIP", "*.dat *.xml *.zip *.gz"), ("All files", "*.*")]
        )
        if not path:
            return

        zip_member = None
        if path.lower().endswith(".zip"):
            # Single-select chooser for inner files (auto-selects if only 1)
            chosen = self._choose_files_in_zip(self, path, multi=False)
            if not chosen:
                return  # user cancelled
            zip_member = chosen[0]

        self._set_status("Parsing target DAT…")

        def parse_target_worker():
            if zip_member:
                data = self._read_zip_member_bytes(path, zip_member)
                if data is None:
                    raise RuntimeError(f"Failed reading ZIP member: {zip_member}")
                return parse_dat_xml_bytes(data)
            else:
                # Handles .dat/.xml/.gz and single-file zips via existing path
                return parse_dat_file(path)

        # After parsing, finish compare as before
        self._run_bg(
            func=parse_target_worker,
            args=(),
            on_done=lambda idx: self._finish_compare(path if not zip_member else f"{path} :: {zip_member}", idx),
            on_err=lambda e: self._error(f"Failed to parse target DAT: {e}")
        )


    def _finish_compare(self, path: str, idx: DatIndex):
        """Finalize compare: compute and render diffs."""
        self._target_index = idx
        self._target_path = path
        if not self._source_index:
            self._error("No source loaded (unexpected).")
            return

        self._set_status("Computing diff…")
        diff = diff_dat(self._source_index, self._target_index)
        self._current_diff = diff

        # Update Summary + tables
        self._render_summary(diff)
        self._fill_games(diff)
        self._fill_roms(diff)

        self._set_status(
            f"Compared: {os.path.basename(self._source_path or '')}  →  {os.path.basename(path)}"
        )


    # ---------- Misc utils ----------
    def _clear_tree(self, tree: ttk.Treeview):
        for i in tree.get_children():
            tree.delete(i)

    def _clear_diff_views(self):
        """Clear all diff Treeviews (games and ROMs)."""
        for t in (
            getattr(self, "games_added_tree", None),
            getattr(self, "games_removed_tree", None),
            getattr(self, "roms_added_tree", None),
            getattr(self, "roms_removed_tree", None),
            getattr(self, "roms_changed_tree", None),
        ):
            if t is not None:
                self._clear_tree(t)

    def _on_appearance_changed(self, new_mode: str) -> None:
        """Switch CustomTkinter appearance and re-apply Treeview styling."""
        try:
            ctk.set_appearance_mode(new_mode)  # "Light" or "Dark"
        except Exception:
            # Be tolerant; if CTk throws, don't crash the app
            pass

        # Re-apply Treeview palette + zebra (your existing function)
        self._style_treeviews()

    def _set_status(self, msg: str):
        self.status_var.set(msg)
        self.update_idletasks()

    def _error(self, msg: str):
        self._set_status("Error.")
        messagebox.showerror("Error", msg)

    def _prompt(self, title: str, prompt: str, default: str = "") -> Optional[str]:
        dlg = ctk.CTkToplevel(self)
        dlg.title(title)
        dlg.transient(self)
        dlg.grab_set()
        dlg.resizable(False, False)

        ctk.CTkLabel(dlg, text=prompt, font=self.FONT_BASE).pack(padx=12, pady=(12, 6))
        var = tk.StringVar(value=default)
        entry = ctk.CTkEntry(dlg, textvariable=var, width=320, font=self.FONT_BASE)
        entry.pack(padx=12, pady=6)
        entry.focus_set()

        res = {"value": None}
        def ok():
            res["value"] = var.get().strip()
            dlg.destroy()

        btns = ctk.CTkFrame(dlg)
        btns.pack(padx=12, pady=(6, 12), fill="x")
        ctk.CTkButton(btns, text="OK", command=ok, font=self.FONT_MED).pack(side="right", padx=6)
        ctk.CTkButton(btns, text="Cancel", command=dlg.destroy, font=self.FONT_MED).pack(side="right", padx=6)

        dlg.update_idletasks()
        self._center_toplevel(dlg)
        dlg.wait_window()
        return res["value"]

    def _run_bg(self, func, args=(), on_done=None, on_err=None):
        def worker():
            if logging.getLogger().hasHandlers():
                try:
                    tname = getattr(func, "__name__", str(func))
                except Exception:
                    tname = str(func)
                logger.debug("BG start: %s args=%r", tname, args)
            try:
                out = func(*args)
            except Exception as e:
                if logging.getLogger().hasHandlers():
                    logger.exception("Background task failed")
                if on_err:
                    self.after(0, lambda: on_err(e))
                return
            if logging.getLogger().hasHandlers():
                logger.debug("BG done: %s", tname)
            if on_done:
                self.after(0, lambda: on_done(out))
        threading.Thread(target=worker, daemon=True).start()

# ---------- Main ----------
def main():
    app = DiffApp()
    app.mainloop()

if __name__ == "__main__":
    import argparse, os, sys, logging, logging.handlers

    parser = argparse.ArgumentParser(description="DAT Diff")
    parser.add_argument(
        "--log-file",
        action="store_true",
        help="Enable rotating file logs at ~/.datdiff/app.log"
    )
    parser.add_argument(
        "--log-stderr",
        action="store_true",
        help="Also emit logs to stderr"
    )
    parser.add_argument(
        "--log-level",
        default="ERROR",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Log level (default: ERROR)"
    )
    args = parser.parse_args()

    # Only configure logging if at least one sink is requested
    if args.log_file or args.log_stderr:
        root = logging.getLogger()
        root.setLevel(getattr(logging, args.log_level))

        fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")

        if args.log_file:
            app_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
            os.makedirs(app_dir, exist_ok=True)
            fh = logging.handlers.RotatingFileHandler(
                os.path.join(app_dir, "app.log"), maxBytes=1_000_000, backupCount=3
            )
            fh.setFormatter(fmt)
            root.addHandler(fh)

        if args.log_stderr:
            sh = logging.StreamHandler(sys.stderr)
            sh.setFormatter(fmt)
            root.addHandler(sh)

        # >>> Emit a startup line so the log file is never blank
        logger = logging.getLogger(__name__)
        logger.debug(
            "Logging enabled: level=%s file=%s stderr=%s",
            args.log_level, args.log_file, args.log_stderr
        )
    main()

