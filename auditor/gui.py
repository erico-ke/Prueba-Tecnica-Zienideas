"""Interfaz gráfica de escritorio (tkinter, incluido en Python).

    python -m auditor.gui            (o: python -m auditor --gui)

Atajos: Ctrl+R actualizar · Ctrl+E exportar informe · Esc cerrar.
"""
import argparse
import queue
import sys
import threading
import tkinter as tk
import webbrowser
from tkinter import font as tkfont
from tkinter import messagebox, ttk

from .auth import AuthError, get_token
from .config import ConfigError, load_config
from .explore import Analysis, analyze_tenant, save_reports
from .models import Severity
from .report import SEVERITY_COLORS, all_findings, anonymize, severity_counts
from .rules import exploration as rx

BG, PANEL, TEXT, MUTED = "#f4f5f7", "#ffffff", "#1d2433", "#5b6475"
OK, WARN, BAD = "#2e7d32", "#b26a00", "#c62828"
LIGHT = {Severity.CRITICAL: "#f6d5d5", Severity.HIGH: "#fbe3e1", Severity.MEDIUM: "#fdf0d8",
         Severity.LOW: "#e3eef7", Severity.INFO: "#eeeeee"}


def classify_permission(perm: str) -> tuple[str, str, str]:
    """(tipo, veredicto, tag de color) de un permiso de aplicación de la herramienta."""
    if rx.is_write(perm):
        return "Escritura", "No debería estar: la herramienta solo lee", "bad"
    if perm in rx.SENSITIVE_READ:
        return "Contenido sensible", f"No debería estar: {rx.SENSITIVE_READ[perm]}", "bad"
    if perm in rx.REQUIRED_PERMISSIONS:
        return "Necesario", "Correcto", "ok"
    return "Innecesario", "Sobra (mínimo privilegio)", "warn"


class App(tk.Tk):
    def __init__(self, anonymized: bool, output_dir: str):
        super().__init__()
        self.anonymized, self.output_dir = anonymized, output_dir
        self.analysis: Analysis | None = None
        self.config_obj = None
        self.findings = []
        self.events: queue.Queue = queue.Queue()  # el hilo de análisis solo habla con la ventana por aquí

        self.title("Detector de concesiones de permisos — Microsoft Graph")
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{int(sw * 0.85)}x{int(sh * 0.85)}+{int(sw * 0.075)}+{int(sh * 0.05)}")
        self.minsize(int(sw * 0.5), int(sh * 0.5))
        self.configure(bg=BG)
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.bind("<Escape>", lambda e: self.destroy())
        self.bind("<Control-r>", lambda e: self.refresh())
        self.bind("<Control-e>", lambda e: self.export())
        self._style()
        self._build()
        self.after(100, self._poll)

    # ------------------------------------------------------------------ layout
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=TEXT, font=("TkDefaultFont", 10))
        line = tkfont.nametofont("TkDefaultFont").metrics("linespace")  # respeta el escalado HiDPI
        s.configure("Treeview", rowheight=int(line * 1.5), background=PANEL, fieldbackground=PANEL)
        s.configure("Treeview.Heading", font=("TkDefaultFont", 10, "bold"))
        s.configure("TNotebook.Tab", padding=(14, 6))
        s.configure("Title.TLabel", font=("TkDefaultFont", 15, "bold"))
        s.configure("Muted.TLabel", foreground=MUTED)
        s.configure("Accent.TButton", font=("TkDefaultFont", 10, "bold"))

    def _build(self):
        top = ttk.Frame(self, padding=(16, 12))
        top.pack(fill="x")
        ttk.Label(top, text="Detector de concesiones de permisos", style="Title.TLabel").pack(side="left")
        ttk.Button(top, text="Cerrar", command=self.destroy).pack(side="right", padx=4)
        self.btn_export = ttk.Button(top, text="Exportar informe", command=self.export, state="disabled")
        self.btn_export.pack(side="right", padx=4)
        self.btn_refresh = ttk.Button(top, text="⟳ Actualizar", style="Accent.TButton", command=self.refresh)
        self.btn_refresh.pack(side="right", padx=4)

        self.status = ttk.Label(self, text="Pulsa «Actualizar» (Ctrl+R) para analizar el tenant.",
                                style="Muted.TLabel", padding=(16, 0))
        self.status.pack(fill="x")

        self.tiles = ttk.Frame(self, padding=(16, 10))
        self.tiles.pack(fill="x")
        self.tile_labels = {}
        for sev in Severity:
            box = tk.Frame(self.tiles, bg=PANEL, highlightthickness=0)
            box.pack(side="left", padx=(0, 10), ipadx=14, ipady=4)
            tk.Frame(box, bg=SEVERITY_COLORS[sev], height=4).pack(fill="x")
            num = tk.Label(box, text="–", font=("TkDefaultFont", 20, "bold"), bg=PANEL, fg=TEXT)
            num.pack(anchor="w", padx=10)
            tk.Label(box, text=sev.value, bg=PANEL, fg=MUTED).pack(anchor="w", padx=10)
            self.tile_labels[sev] = num
        self.summary = ttk.Label(self, text="", style="Muted.TLabel", padding=(16, 0, 16, 8))
        self.summary.pack(fill="x")
        self.summary.bind("<Configure>", lambda e: self.summary.configure(wraplength=e.width - 32))

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        nb.add(self._findings_tab(nb), text="Hallazgos")
        nb.add(self._permissions_tab(nb), text="Permisos de la herramienta")
        nb.add(self._matrix_tab(nb), text="Matriz de acceso")

    def _tree(self, parent, columns: list[tuple[str, str, int]]):
        frame = ttk.Frame(parent)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", selectmode="browse")
        for key, title, width in columns:
            tree.heading(key, text=title)
            tree.column(key, width=width, minwidth=40, stretch=width >= 300)
        sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return frame, tree

    def _findings_tab(self, nb):
        pane = ttk.PanedWindow(nb, orient="horizontal")
        left, self.ftree = self._tree(pane, [("sev", "Severidad", 110), ("id", "ID", 100),
                                             ("title", "Hallazgo", 400)])
        for sev in Severity:
            self.ftree.tag_configure(sev.name, background=LIGHT[sev])
        self.ftree.bind("<<TreeviewSelect>>", self._show_finding)
        pane.add(left, weight=1)

        self.detail = tk.Text(pane, wrap="word", bg=PANEL, fg=TEXT, relief="flat", padx=14, pady=12,
                              font=("TkDefaultFont", 10), state="disabled")
        self.detail.tag_configure("h", font=("TkDefaultFont", 13, "bold"), spacing3=6)
        self.detail.tag_configure("label", font=("TkDefaultFont", 10, "bold"), spacing1=10)
        self.detail.tag_configure("item", lmargin1=12, lmargin2=24)
        for sev in Severity:
            self.detail.tag_configure(sev.name, foreground=SEVERITY_COLORS[sev], font=("TkDefaultFont", 10, "bold"))
        pane.add(self.detail, weight=1)
        pane.bind("<Map>", lambda e: pane.after(50, lambda: pane.sashpos(0, int(pane.winfo_width() * 0.55))))
        return pane

    def _permissions_tab(self, nb):
        frame, self.ptree = self._tree(nb, [("perm", "Permiso", 330), ("kind", "Tipo", 210),
                                            ("verdict", "Veredicto", 560)])
        self.ptree.tag_configure("bad", background="#fbe3e1", foreground=BAD)
        self.ptree.tag_configure("warn", background="#fdf0d8", foreground=WARN)
        self.ptree.tag_configure("ok", background="#e3f3e5", foreground=OK)
        self.ptree.tag_configure("muted", foreground=MUTED)
        return frame

    def _matrix_tab(self, nb):
        frame, self.mtree = self._tree(nb, [("ok", "", 40), ("status", "HTTP", 60), ("label", "Recurso", 230),
                                            ("endpoint", "Endpoint", 380), ("perm", "Permiso documentado", 320),
                                            ("note", "Observación", 300)])
        self.mtree.tag_configure("odd", background="#fdf0d8")
        self.mtree.tag_configure("denied", foreground=MUTED)
        return frame

    # ------------------------------------------------------------------ acciones
    def refresh(self):
        if str(self.btn_refresh["state"]) == "disabled":
            return
        self.btn_refresh.configure(state="disabled")
        self.btn_export.configure(state="disabled")
        self._status("Conectando con el tenant...")
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        """Hilo secundario: nunca toca tkinter, solo encola mensajes."""
        try:
            self.config_obj = load_config()
            token = get_token(self.config_obj)
            analysis = analyze_tenant(self.config_obj, token, progress=lambda m: self.events.put(("status", m)))
            self.events.put(("done", analysis))
        except (ConfigError, AuthError, Exception) as e:  # noqa: BLE001 — cualquier fallo se muestra al usuario
            self.events.put(("error", str(e)))

    def _poll(self):
        """Hilo principal: procesa los mensajes del análisis cada 100 ms."""
        try:
            while True:
                kind, payload = self.events.get_nowait()
                {"status": self._status, "done": self._populate, "error": self._fail}[kind](payload)
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def _fail(self, message: str):
        self.btn_refresh.configure(state="normal")
        self._status("Error: " + message.splitlines()[0])
        messagebox.showerror("No se pudo analizar el tenant", message)

    def _status(self, text: str):
        self.status.configure(text=text)

    def export(self):
        if not self.analysis:
            return
        paths = save_reports(self._result(), self.config_obj, self.analysis.generated, self.output_dir, self.anonymized)
        if messagebox.askyesno("Informe exportado", "Guardado en:\n" + "\n".join(map(str, paths)) + "\n\n¿Abrir el HTML?"):
            webbrowser.open(paths[0].resolve().as_uri())

    def _result(self):
        return anonymize(self.analysis.result) if self.anonymized else self.analysis.result

    # ------------------------------------------------------------------ pintar datos
    def _populate(self, analysis: Analysis):
        self.analysis = analysis
        result = self._result()

        for sev, n in severity_counts(result.sections).items():
            self.tile_labels[Severity(sev)].configure(text=str(n))
        self.summary.configure(text="   ".join(f"{k}: {v}" for k, v in result.summary.items()))

        self.ftree.delete(*self.ftree.get_children())
        self.findings = all_findings(result.sections)
        for i, f in enumerate(self.findings):
            self.ftree.insert("", "end", iid=str(i), values=(f.severity.value, f.id, f.title),
                              tags=(f.severity.name,))
        if self.findings:
            self.ftree.selection_set("0")

        self.ptree.delete(*self.ptree.get_children())
        rows = [(r, *classify_permission(r)) for r in analysis.roles]
        order = {"bad": 0, "warn": 1, "ok": 2}
        for perm, kind, verdict, tag in sorted(rows, key=lambda r: (order[r[3]], r[0])):
            self.ptree.insert("", "end", values=(perm, kind, verdict), tags=(tag,))
        for missing in (p for p in rx.REQUIRED_PERMISSIONS if p not in analysis.roles):
            self.ptree.insert("", 0, values=(missing, "Necesario", "FALTA: concederlo"), tags=("bad",))
        for scope in analysis.delegated:
            self.ptree.insert("", "end", values=(scope, "Delegado", "Sin uso: la herramienta no inicia sesión como usuario"),
                              tags=("muted",))

        self.mtree.delete(*self.mtree.get_children())
        roles = set(analysis.roles)
        for p in analysis.probes:
            granted = roles & set(p.permissions)
            if p.ok and not granted:
                note, tag = "Accesible SIN el permiso documentado", "odd"
            elif not p.ok and granted and p.unlicensed:
                note, tag = "Permiso concedido, falta licencia (latente)", "odd"
            elif not p.ok and granted:
                note, tag = f"Permiso concedido, servicio responde {p.code}", "odd"
            elif p.ok:
                note, tag = f"{p.count} elementos" if p.count is not None else "OK", ""
            else:
                note, tag = "Sin permiso (esperado)", "denied"
            self.mtree.insert("", "end", values=("✔" if p.ok else "✘", p.status, p.label, p.endpoint,
                                                 " / ".join(p.permissions), note), tags=(tag,) if tag else ())

        local = analysis.generated.astimezone()
        self._status(f"Última actualización: {local:%d/%m/%Y %H:%M:%S}"
                     + ("  ·  datos anonimizados" if self.anonymized else "")
                     + "   —   Ctrl+R actualizar · Ctrl+E exportar · Esc cerrar")
        self.btn_refresh.configure(state="normal")
        self.btn_export.configure(state="normal")

    def _show_finding(self, _event=None):
        sel = self.ftree.selection()
        if not sel:
            return
        f = self.findings[int(sel[0])]
        t = self.detail
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("end", f"{f.severity.value.upper()}  ·  {f.id}  ·  {f.category}\n", f.severity.name)
        t.insert("end", f.title + "\n", "h")
        t.insert("end", f.description + "\n")
        t.insert("end", "Qué hacer\n", "label")
        t.insert("end", f.recommendation + "\n")
        if f.affected:
            t.insert("end", f"Indicadores / objetos afectados ({len(f.affected)})\n", "label")
            for a in f.affected:
                t.insert("end", f"•  {a}\n", "item")
        t.configure(state="disabled")


def run(anonymized: bool = False, output_dir: str = "reports") -> int:
    app = App(anonymized, output_dir)
    app.after(200, app.refresh)  # analiza nada más abrir
    app.mainloop()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Interfaz gráfica del detector de concesiones de permisos")
    parser.add_argument("--anonymize", action="store_true")
    parser.add_argument("-o", "--output-dir", default="reports")
    args = parser.parse_args()
    return run(args.anonymize, args.output_dir)


if __name__ == "__main__":
    sys.exit(main())
