# metasploit_gui_msfrpc.py
# Python 3.9+ | pip install pymetasploit3 tkinter ttkthemes

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from ttkthemes import ThemedTk
from pymetasploit3.msfrpc import MsfRpcClient
from pymetasploit3.msfconsole import MsfRpcConsole
import threading
import time
import os

class MetasploitGUI:
    def __init__(self):
        # Hauptfenster mit Dark Theme
        self.root = ThemedTk(theme="equilux")  # eines der schönsten Dark Themes
        self.root.title("Metasploit Pro GUI - msfrpc")
        self.root.geometry("1400x900")
        self.root.configure(bg="#1e1e1e")

        # msfrpc Verbindung
        self.client = None
        self.console_reader = None
        self.connected = False

        self.create_widgets()
        self.connect_to_msfrpcd()

    def create_widgets(self):
        # === Top Bar - Verbindung ===
        top_frame = ttk.Frame(self.root)
        top_frame.pack(fill=tk.X, padx=10, pady=8)

        ttk.Label(top_frame, text="msfrpcd Verbindung:", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        
        self.conn_status = ttk.Label(top_frame, text="Nicht verbunden", foreground="#ff5555")
        self.conn_status.pack(side=tk.LEFT, padx=(10,20))

        ttk.Button(top_frame, text="Verbinden", command=self.connect_dialog).pack(side=tk.RIGHT)

        # === Paned Window für Layout ===
        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # === Linke Seite: Module Browser ===
        left_frame = ttk.Frame(paned)
        paned.add(left_frame, weight=1)

        ttk.Label(left_frame, text="Module Browser", font=("Segoe UI", 11, "bold")).pack(anchor=tk.W, padx=5)
        
        # Suchleiste
        search_frame = ttk.Frame(left_frame)
        search_frame.pack(fill=tk.X, padx=5, pady=5)
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *args: self.filter_modules())
        ttk.Entry(search_frame, textvariable=self.search_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(search_frame, text="Suche", command=self.filter_modules).pack(side=tk.RIGHT)

        # Treeview für Module
        self.tree = ttk.Treeview(left_frame, columns=("type", "path"), show="tree headings")
        self.tree.heading("#0", text="Name")
        self.tree.heading("type", text="Typ")
        self.tree.heading("path", text="Pfad")
        self.tree.column("#0", width=280)
        self.tree.column("type", width=80)
        self.tree.column("path", width=200)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.tree.bind("<<TreeviewSelect>>", self.on_module_select)
        self.tree.bind("<Double-1>", self.use_selected_module)

        # === Rechte Seite ===
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=3)

        # Notebook für Tabs
        self.notebook = ttk.Notebook(right_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab 1: Modul Details & Options
        self.tab_options = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_options, text="Modul Optionen")

        # Tab 2: Console
        self.tab_console = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_console, text="Console")

        # Tab 3: Sessions
        self.tab_sessions = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_sessions, text="Sessions")

        # === Modul Optionen Tab ===
        self.options_frame = ttk.LabelFrame(self.tab_options, text=" Optionen ")
        self.options_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.options_canvas = tk.Canvas(self.options_frame)
        scrollbar = ttk.Scrollbar(self.options_frame, orient="vertical", command=self.options_canvas.yview)
        self.options_inner = ttk.Frame(self.options_canvas)

        self.options_inner.bind(
            "<Configure>",
            lambda e: self.options_canvas.configure(scrollregion=self.options_canvas.bbox("all"))
        )

        self.options_canvas.create_window((0, 0), window=self.options_inner, anchor="nw")
        self.options_canvas.configure(yscrollcommand=scrollbar.set)

        self.options_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Buttons unter Optionen
        btn_frame = ttk.Frame(self.tab_options)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(btn_frame, text="Check", command=self.check_module).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Exploit / Run", style="Danger.TButton", command=self.run_module).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Info", command=self.show_info).pack(side=tk.LEFT, padx=5)

        # === Console Tab ===
        self.console_text = tk.Text(
            self.tab_console,
            bg="#1e1e1e",
            fg="#f8f8f2",
            insertbackground="#ff5555",
            font=("Consolas", 11),
            wrap=tk.NONE
        )
        self.console_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.console_text.config(state=tk.DISABLED)

        # Console Input
        console_input_frame = ttk.Frame(self.tab_console)
        console_input_frame.pack(fill=tk.X, padx=5, pady=5)
        self.console_input = ttk.Entry(console_input_frame)
        self.console_input.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.console_input.bind("<Return>", self.send_console_command)
        ttk.Button(console_input_frame, text="Send", command=self.send_console_command).pack(side=tk.RIGHT)

        # === Sessions Tab ===
        self.sessions_tree = ttk.Treeview(self.tab_sessions, columns=("ID", "Type", "Info", "Tunnel"), show="headings")
        self.sessions_tree.heading("ID", text="ID")
        self.sessions_tree.heading("Type", text="Typ")
        self.sessions_tree.heading("Info", text="Info")
        self.sessions_tree.heading("Tunnel", text="Tunnel")
        self.sessions_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.sessions_tree.bind("<Double-1>", self.interact_with_session)

        ttk.Button(self.tab_sessions, text="Aktualisieren", command=self.refresh_sessions).pack(pady=5)

        # Roter Button Style
        style = ttk.Style()
        style.configure("Danger.TButton", foreground="white", background="#cc0000")
        style.map("Danger.TButton", background=[("active", "#ee4444")])

    def connect_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("msfrpcd Verbindung")
        dialog.geometry("400x300")
        dialog.configure(bg="#2d2d2d")
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text="Passwort:").pack(pady=10)
        pw = ttk.Entry(dialog, show="*")
        pw.pack(padx=20, fill=tk.X)
        pw.insert(0, "abc123")

        ttk.Label(dialog, text="Host:").pack(pady=(20,5))
        host = ttk.Entry(dialog)
        host.pack(padx=20, fill=tk.X)
        host.insert(0, "127.0.0.1")

        ttk.Label(dialog, text="Port:").pack(pady=(10,5))
        port = ttk.Entry(dialog)
        port.pack(padx=20, fill=tk.X)
        port.insert(0, "55553")

        def connect():
            threading.Thread(target=self.connect_to_msfrpcd, args=(pw.get(), host.get(), port.get()), daemon=True).start()
            dialog.destroy()

        ttk.Button(dialog, text="Verbinden", command=connect).pack(pady=20)

    def connect_to_msfrpcd(self, password="abc123", host="127.0.0.1", port="55553"):
        try:
            self.client = MsfRpcClient(password, server=host, port=int(port), ssl=True)
            self.console_reader = MsfRpcConsole(self.client.core)
            self.connected = True
            self.conn_status.config(text="Verbunden", foreground="#50fa7b")
            self.root.title(f"Metasploit Pro GUI - Verbunden mit {host}:{port}")
            self.load_all_modules()
            self.start_console_reader()
            self.refresh_sessions()
        except Exception as e:
            messagebox.showerror("Verbindung fehlgeschlagen", str(e))
            self.conn_status.config(text="Verbindung fehlgeschlagen", foreground="#ff5555")

    def load_all_modules(self):
        if not self.connected: return
        self.tree.delete(*self.tree.get_children())
        
        categories = {
            "exploit": ("Exploits", self.client.modules.exploits),
            "auxiliary": ("Auxiliary", self.client.modules.auxiliary),
            "post": ("Post", self.client.modules.post),
            "payload": ("Payloads", self.client.modules.payloads),
            "encoder": ("Encoders", self.client.modules.encoders),
            "nop": ("NOPs", self.client.modules.nops),
        }

        for mtype, (display, module_list) in categories.items():
            parent = self.tree.insert("", "end", text=display, open=False)
            for mod in sorted(module_list):
                name = mod.split("/")[-1]
                self.tree.insert(parent, "end", text=name, values=(mtype, mod))

    def filter_modules(self):
        search = self.search_var.get().lower()
        self.tree.delete(*self.tree.get_children())
        # Einfache Volltextsuche über alle Module
        for result in self.client.modules.search(search):
            path = result['fullname']
            name = path.split("/")[-1]
            mtype = result['type']
            parent = None
            for item in self.tree.get_children():
                if self.tree.item(item, "text") == mtype.capitalize() + "s":
                    parent = item
                    break
            if not parent:
                parent = self.tree.insert("", "end", text=mtype.capitalize() + "s", open=True)
            self.tree.insert(parent, "end", text=name, values=(mtype, path))

    def on_module_select(self, event=None):
        selection = self.tree.selection()
        if not selection: return
        item = self.tree.item(selection[0])
        if item["values"]:
            self.use_module(item["values"][1])

    def use_selected_module(self, event=None):
        self.on_module_select()

    def use_module(self, fullpath):
        try:
            mtype = fullpath.split("/")[0]
            self.client.modules.use(mtype, fullpath)
            self.current_module = self.client.modules.module
            self.show_module_options()
            self.append_console(f"[+] use {fullpath}\n")
        except Exception as e:
            messagebox.showerror("Fehler", str(e))

    def show_module_options(self):
        for widget in self.options_inner.winfo_children():
            widget.destroy()

        if not hasattr(self, 'current_module'):
            return

        options = self.current_module.options
        required = self.current_module.missing_required

        row = 0
        for opt in sorted(options):
            info = self.current_module.option_info(opt)
            is_required = opt in required

            ttk.Label(self.options_inner, text=opt, font=("Consolas", 10, "bold")).grid(row=row, column=0, sticky="w", padx=5, pady=3)
            ttk.Label(self.options_inner, text=info.get('desc', ''), foreground="#888888").grid(row=row, column=1, sticky="w", padx=20)

            current = self.current_module[opt]
            var = tk.StringVar(value=current if current is not None else "")

            entry = ttk.Entry(self.options_inner, textvariable=var, width=50)
            entry.grid(row=row, column=2, padx=5, pady=3)

            def setter(o=opt, v=var):
                self.current_module[o] = v.get()

            var.trace("w", lambda *_, o=opt, v=var: setter(o, v))

            if is_required:
                ttk.Label(self.options_inner, text=" *", foreground="#ff5555").grid(row=row, column=3)

            row += 1

    def check_module(self):
        if hasattr(self, 'current_module'):
            threading.Thread(target=lambda: self.append_console(self.current_module.check() + "\n"), daemon=True).start()

    def run_module(self):
        if not hasattr(self, 'current_module'):
            return
        threading.Thread(target=self.execute_module, daemon=True).start()

    def execute_module(self):
        try:
            result = self.current_module.execute(**self.current_module.runoptions)
            self.append_console(f"[+] Modul gestartet: {result.get('job_id')}\n")
            time.sleep(2)
            self.refresh_sessions()
        except Exception as e:
            self.append_console(f"[-] Fehler: {e}\n")

    def show_info(self):
        if hasattr(self, 'current_module'):
            info = self.current_module.info
            text = f"Name: {info.get('name')}\nDescription: {info.get('description')}\nAuthor: {', '.join(info.get('authors', []))}\n"
            messagebox.showinfo("Module Info", text)

    def start_console_reader(self):
        def read():
            while self.connected:
                try:
                    line = self.console_reader.read()
                    if line:
                        self.append_console(line['data'])
                except:
                    time.sleep(0.1)
        threading.Thread(target=read, daemon=True).start()

    def append_console(self, text):
        self.console_text.config(state=tk.NORMAL)
        self.console_text.insert(tk.END, text)
        self.console_text.see(tk.END)
        self.console_text.config(state=tk.DISABLED)

    def send_console_command(self, event=None):
        cmd = self.console_input.get().strip()
        if cmd and self.console_reader:
            self.console_reader.write(cmd + "\n")
            self.console_input.delete(0, tk.END)
            self.append_console(f"msf6 > {cmd}\n")

    def refresh_sessions(self):
        if not self.connected: return
        for i in self.sessions_tree.get_children():
            self.sessions_tree.delete(i)
        for sid, sess in self.client.sessions.list.items():
            info = sess.get('info', '')
            tunnel = f"{sess.get('session_host')} -> {sess.get('tunnel_peer')}"
            self.sessions_tree.insert("", "end", values=(sid, sess['type'], info, tunnel))

    def interact_with_session(self, event=None):
        selection = self.sessions_tree.selection()
        if not selection: return
        sid = self.sessions_tree.item(selection[0])['values'][0]
        shell = self.client.sessions.session(int(sid))
        self.append_console(f"\n[*] Interaktive Session {sid} geöffnet (Meterpreter/Shell)\n")
        # Hier könntest du ein separates Shell-Fenster öffnen – für Einfachheit hier im Console-Tab

    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    def on_close(self):
        if messagebox.askokcancel("Beenden", "Metasploit GUI schließen?"):
            self.connected = False
            self.root.destroy()

if __name__ == "__main__":
    app = MetasploitGUI()
    app.run()