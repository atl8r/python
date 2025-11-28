import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
import subprocess
import threading
import queue
import os

class MsfGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MSFConsole GUI")
        self.root.configure(bg='#1e1e1e')
        self.root.geometry("1200x800")

        # Dark theme styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#1e1e1e')
        self.style.configure('TLabel', background='#1e1e1e', foreground='#ffffff')
        self.style.configure('TButton', background='#333333', foreground='#ffffff', borderwidth=0)
        self.style.map('TButton', background=[('active', '#cc0000')], foreground=[('active', '#ffffff')])
        self.style.configure('TEntry', fieldbackground='#333333', foreground='#ffffff', insertcolor='#ffffff')
        self.style.configure('Treeview', background='#252526', foreground='#ffffff', fieldbackground='#252526')
        self.style.map('Treeview', background=[('selected', '#cc0000')])
        self.style.configure('Treeview.Heading', background='#333333', foreground='#ffffff')
        self.style.configure('Vertical.TScrollbar', background='#333333', troughcolor='#1e1e1e', arrowcolor='#ffffff')

        # Queue for thread-safe output
        self.output_queue = queue.Queue()

        # Main frame
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Left panel: Module tree
        self.left_frame = ttk.Frame(self.main_frame)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5)

        ttk.Label(self.left_frame, text="Modules").pack(pady=5)
        self.module_tree = ttk.Treeview(self.left_frame, columns=('Name',), show='tree headings')
        self.module_tree.heading('#0', text='Category')
        self.module_tree.heading('Name', text='Module')
        self.module_tree.pack(fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(self.left_frame, orient='vertical', command=self.module_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.module_tree.configure(yscrollcommand=scrollbar.set)

        # Load modules button
        load_btn = ttk.Button(self.left_frame, text="Load Modules", command=self.load_modules)
        load_btn.pack(pady=5)

        # Right panel: Console and controls
        self.right_frame = ttk.Frame(self.main_frame)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)

        # Command input
        input_frame = ttk.Frame(self.right_frame)
        input_frame.pack(fill=tk.X, pady=5)

        self.cmd_entry = ttk.Entry(input_frame)
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.cmd_entry.bind('<Return>', self.execute_command)

        run_btn = ttk.Button(input_frame, text="Run", command=self.execute_command)
        run_btn.pack(side=tk.RIGHT)

        # Output console
        self.output_text = scrolledtext.ScrolledText(self.right_frame, bg='#252526', fg='#ffffff', insertbackground='#ffffff', font=('Consolas', 10))
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(self.right_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_label.pack(fill=tk.X, pady=5)

        # MSF process
        self.msf_proc = None
        self.start_msfconsole()

        # Periodic check for output
        self.root.after(100, self.process_output)

    def start_msfconsole(self):
        """Start msfconsole in a subprocess."""
        try:
            self.msf_proc = subprocess.Popen(
                ['msfconsole', '-q'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            threading.Thread(target=self.read_output, daemon=True).start()
            self.status_var.set("msfconsole started")
        except Exception as e:
            self.status_var.set(f"Error starting msfconsole: {e}")

    def read_output(self):
        """Read output from msfconsole subprocess."""
        while True:
            if self.msf_proc and self.msf_proc.stdout:
                line = self.msf_proc.stdout.readline()
                if line:
                    self.output_queue.put(line.strip() + '\n')
                else:
                    break

    def process_output(self):
        """Process queued output and update GUI."""
        try:
            while not self.output_queue.empty():
                line = self.output_queue.get_nowait()
                self.output_text.config(state=tk.NORMAL)
                self.output_text.insert(tk.END, line)
                self.output_text.see(tk.END)
                self.output_text.config(state=tk.DISABLED)
        except queue.Empty:
            pass
        self.root.after(100, self.process_output)

    def execute_command(self, event=None):
        """Execute command in msfconsole."""
        cmd = self.cmd_entry.get().strip()
        if cmd and self.msf_proc:
            self.msf_proc.stdin.write(cmd + '\n')
            self.msf_proc.stdin.flush()
            self.cmd_entry.delete(0, tk.END)
            self.output_text.config(state=tk.NORMAL)
            self.output_text.insert(tk.END, f"> {cmd}\n")
            self.output_text.see(tk.END)
            self.output_text.config(state=tk.DISABLED)

    def load_modules(self):
        """Load Metasploit modules into the treeview."""
        self.module_tree.delete(*self.module_tree.get_children())
        # Simulate loading modules; in reality, parse 'search' or use msfrpc for full list
        categories = {
            'exploits': ['windows/smb/ms08_067_netapi', 'unix/webapp/php_xmlrpc_eval'],
            'auxiliary': ['scanner/http/dir_scanner', 'admin/http/tomcat_administration'],
            'post': ['windows/gather/enum_applications', 'multi/gather/firefox_creds'],
            'payloads': ['windows/shell_reverse_tcp', 'linux/x86/shell_reverse_tcp'],
            'encoders': ['x86/shikata_ga_nai', 'mipsbe/byte_add'],
            'nops': ['x86/opty2', 'armle/simple']
        }
        for cat, mods in categories.items():
            cat_id = self.module_tree.insert('', 'end', text=cat)
            for mod in mods:
                self.module_tree.insert(cat_id, 'end', values=(mod,))
        self.status_var.set("Modules loaded")

    def close(self):
        if self.msf_proc:
            self.msf_proc.terminate()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = MsfGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.close)
    root.mainloop()