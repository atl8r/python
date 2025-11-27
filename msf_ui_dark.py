#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Benutzerfreundliche Dark-Theme-UI für msfconsole – mit Hilfestellungen (CustomTkinter)

import subprocess
import threading
import customtkinter as ctk
import tkinter as tk
from tkinter import scrolledtext, messagebox
import sys
import os

ctk.set_appearance_mode("dark")  # Dark Theme aktivieren
ctk.set_default_color_theme("dark-blue")  # Blaues Dark-Theme

class MsfUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MSFconsole UI – Dark Edition")
        self.root.geometry("900x700")
        self.root.configure(bg="#1e1e1e")

        # Output-Textbereich (scrolled, mit Dark Theme)
        self.output_text = ctk.CTkTextbox(root, wrap="word", font=("Courier", 10), fg_color="#000", text_color="#0f0")
        self.output_text.pack(padx=10, pady=10, fill=ctk.BOTH, expand=True)
        self.output_text.insert("0.0", "Starte msfconsole...\n")
        self.output_text.configure(state="disabled")

        # Quick-Tipps-Bereich (Hilfestellung unten)
        self.tips_label = ctk.CTkLabel(root, text="Quick-Tipps: Drücke Enter zum Senden. Hover über Buttons für Hilfe. Gängige Kommandos: search, use, set, exploit.", 
                                       font=("Arial", 10), text_color="#aaa", anchor="w")
        self.tips_label.pack(fill=ctk.X, padx=10, pady=5)

        # Eingabeframe
        self.input_frame = ctk.CTkFrame(root)
        self.input_frame.pack(fill=ctk.X, padx=10, pady=5)
        
        self.input_label = ctk.CTkLabel(self.input_frame, text="Kommando:", font=("Arial", 10))
        self.input_label.pack(side=ctk.LEFT)
        
        self.input_entry = ctk.CTkEntry(self.input_frame, font=("Courier", 10), placeholder_text="z.B. search eternalblue")
        self.input_entry.pack(side=ctk.LEFT, fill=ctk.X, expand=True, padx=5)
        self.input_entry.bind("<Return>", self.send_command)
        self.input_entry.bind("<Tab>", self.autocomplete)  # Auto-Vervollständigung mit Tab
        
        # Buttons mit Tooltips
        self.send_button = ctk.CTkButton(self.input_frame, text="Senden", command=self.send_command, fg_color="#4CAF50")
        self.send_button.pack(side=ctk.LEFT, padx=5)
        self.add_tooltip(self.send_button, "Kommando an msfconsole senden (oder Enter drücken)")

        self.clear_button = ctk.CTkButton(self.input_frame, text="Clear Output", command=self.clear_output, fg_color="#FFA500")
        self.clear_button.pack(side=ctk.LEFT, padx=5)
        self.add_tooltip(self.clear_button, "Output-Fenster leeren")

        self.help_button = ctk.CTkButton(self.input_frame, text="Hilfe", command=self.show_help, fg_color="#2196F3")
        self.help_button.pack(side=ctk.LEFT, padx=5)
        self.add_tooltip(self.help_button, "Zeige detaillierte Hilfestellungen und Kommandos")

        self.quit_button = ctk.CTkButton(self.input_frame, text="Beenden", command=self.quit_msf, fg_color="#f44336")
        self.quit_button.pack(side=ctk.LEFT, padx=5)
        self.add_tooltip(self.quit_button, "msfconsole und UI sauber beenden")

        # Auto-Vervollständigungs-Liste (gängige Kommandos)
        self.common_commands = ["search ", "use ", "set ", "show options", "exploit", "run", "back", "info ", "db_status", "workspace "]

        # Starte msfconsole
        self.msf_proc = None
        self.start_msf()

    def add_tooltip(self, widget, text):
        """Einfache Tooltip-Funktion (hover für Hilfe)"""
        def enter(event): self.tooltip = ctk.CTkLabel(widget, text=text, fg_color="#333", text_color="#fff", corner_radius=5); self.tooltip.place(relx=0.5, rely=1.1, anchor="n")
        def leave(event): self.tooltip.destroy()
        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)

    def autocomplete(self, event):
        """Einfache Auto-Vervollständigung mit Tab"""
        current = self.input_entry.get()
        for cmd in self.common_commands:
            if cmd.startswith(current):
                self.input_entry.delete(0, ctk.END)
                self.input_entry.insert(0, cmd)
                break

    def show_help(self):
        """Hilfe-Pop-up mit detaillierten Tipps"""
        help_text = """
Willkommen zur msfconsole UI – Hilfestellungen:

Grundlegende Kommandos:
- search <keyword>: Suche nach Modulen (z.B. search eternalblue)
- use <modul>: Wähle ein Modul (z.B. use exploit/windows/smb/ms17_010_eternalblue)
- show options: Zeige Optionen des Moduls
- set <option> <wert>: Setze eine Option (z.B. set RHOSTS 192.168.1.100)
- exploit oder run: Starte den Exploit
- back: Zum vorherigen Modul zurück
- exit: Beende msfconsole (oder nutze den Beenden-Button)

Tipps:
- Stelle sicher, du bist autorisiert – nur für legale Tests!
- Für Datenbank: db_status prüfen, workspace -a <name> für neue Workspaces.
- Fehler? Überprüfe den Output und starte neu.

Mehr Infos: msfconsole -h im Eingabefeld.
"""
        messagebox.showinfo("Hilfestellungen für msfconsole", help_text)

    def start_msf(self):
        try:
            self.msf_proc = subprocess.Popen(
                ["msfconsole", "-q"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            threading.Thread(target=self.read_output, daemon=True).start()
        except FileNotFoundError:
            self.output_text.configure(state="normal")
            self.output_text.insert("end", "FEHLER: msfconsole nicht gefunden! Installiere Metasploit.\n")
            self.output_text.configure(state="disabled")

    def read_output(self):
        while True:
            if self.msf_proc and self.msf_proc.stdout:
                line = self.msf_proc.stdout.readline()
                if line:
                    self.output_text.configure(state="normal")
                    self.output_text.insert("end", line)
                    self.output_text.see("end")  # Auto-Scroll
                    self.output_text.configure(state="disabled")
                else:
                    break

    def send_command(self, event=None):
        cmd = self.input_entry.get().strip()
        if cmd and self.msf_proc:
            self.msf_proc.stdin.write(cmd + "\n")
            self.msf_proc.stdin.flush()
            self.input_entry.delete(0, ctk.END)
            self.output_text.configure(state="normal")
            self.output_text.insert("end", f"> {cmd}\n")
            self.output_text.configure(state="disabled")

    def clear_output(self):
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", ctk.END)
        self.output_text.configure(state="disabled")

    def quit_msf(self):
        if self.msf_proc:
            self.msf_proc.stdin.write("exit\n")
            self.msf_proc.stdin.flush()
            self.msf_proc.wait(timeout=5)
        self.root.quit()

if __name__ == "__main__":
    root = ctk.CTk()
    app = MsfUI(root)
    root.mainloop()
