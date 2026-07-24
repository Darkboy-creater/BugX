# ============================================
# TermuxX v3.0 - Admin Panel Finder
# 500+ common admin paths check
# Author: You
# ============================================

import threading
import time
import os
from core.colors import Colors
from core.web_engine import WebEngine


class AdminFinder:
    """
    Admin Panel Finder
    Common admin paths check karta hai
    """

    def __init__(self):
        self.web = WebEngine()
        self.target_url = None
        self.wordlist_path = "data/wordlists/admin_paths.txt"
        self.threads = 30
        self.found = []
        self.lock = threading.Lock()
        self.checked = 0
        self.total = 0

    def configure(self):
        """Settings"""
        print(Colors.info(
            "=== ADMIN PANEL FINDER ===\n"
        ))

        url = input(
            Colors.input_prompt(
                "Target URL (e.g., http://example.com): "
            )
        ).strip()
        if not url:
            print(Colors.error("URL zaroori hai!"))
            return False
        self.target_url = self.web.normalize_url(url)

        wl = input(
            Colors.input_prompt(
                f"Wordlist "
                f"(default: {self.wordlist_path}): "
            )
        ).strip()
        if wl:
            self.wordlist_path = wl

        th = input(
            Colors.input_prompt(
                "Threads (default 30): "
            )
        ).strip()
        if th:
            try:
                self.threads = int(th)
            except:
                pass

        return True

    def check_path(self, path):
        """Ek admin path check karta hai"""
        url = f"{self.target_url}/{path}"
        resp = self.web.get(url, follow=False)

        with self.lock:
            self.checked += 1

        if resp:
            code = resp.status_code
            length = len(resp.text)

            if code == 200:
                # Check for login-related keywords
                login_keywords = [
                    'login', 'password', 'username',
                    'sign in', 'signin', 'log in',
                    'admin', 'dashboard', 'panel',
                    'auth', 'token', 'csrf'
                ]
                has_login = any(
                    kw in resp.text.lower()
                    for kw in login_keywords
                )

                status = "FOUND"
                if has_login:
                    status = "LOGIN PAGE"

                with self.lock:
                    self.found.append({
                        'path': path,
                        'url': url,
                        'status': code,
                        'type': status,
                        'length': length
                    })
                    color = (
                        Colors.GREEN
                        if has_login
                        else Colors.CYAN
                    )
                    print(
                        f"  {color}[{code}]"
                        f"{Colors.RESET} "
                        f"{url:<60} "
                        f"[{status}] "
                        f"Size: {length}"
                    )

            elif code in [301, 302, 303, 307, 308]:
                location = resp.headers.get(
                    'Location', 'N/A'
                )
                with self.lock:
                    self.found.append({
                        'path': path,
                        'url': url,
                        'status': code,
                        'type': 'REDIRECT',
                        'redirect': location,
                        'length': length
                    })
                    print(
                        f"  {Colors.YELLOW}[{code}]"
                        f"{Colors.RESET} "
                        f"{url:<60} "
                        f"-> {location[:40]}"
                    )

            elif code == 403:
                with self.lock:
                    self.found.append({
                        'path': path,
                        'url': url,
                        'status': code,
                        'type': 'FORBIDDEN',
                        'length': length
                    })
                    print(
                        f"  {Colors.PURPLE}[{code}]"
                        f"{Colors.RESET} "
                        f"{url:<60} "
                        f"[FORBIDDEN - Exists!]"
                    )

    def run(self):
        """Finder start"""
        if not self.configure():
            return

        # Load wordlist
        if os.path.exists(self.wordlist_path):
            paths = self.web.load_wordlist(
                self.wordlist_path
            )
        else:
            print(Colors.warning(
                "Wordlist not found. "
                "Using built-in paths..."
            ))
            paths = [
                "admin", "administrator", "admin/login",
                "admin.php", "admin.html", "admin/index",
                "admin/dashboard", "wp-admin",
                "wp-login.php", "login", "login.php",
                "signin", "cpanel", "dashboard",
                "panel", "manager", "backend",
                "cms/admin", "phpmyadmin", "webadmin",
                "siteadmin", "controlpanel", "modcp",
                "superadmin", "portal/admin",
                "user/login", "member/login",
                "system/admin", "auth/login",
                "accounts/login", "adminer.php",
            ]

        self.total = len(paths)

        print(Colors.info(
            f"\nTarget: {self.target_url}"
        ))
        print(Colors.info(
            f"Paths: {self.total}"
        ))
        print(Colors.info(
            f"Threads: {self.threads}"
        ))
        print(Colors.info("=" * 70))

        start_time = time.time()
        thread_list = []

        for path in paths:
            t = threading.Thread(
                target=self.check_path,
                args=(path,)
            )
            thread_list.append(t)
            t.start()

            if len(thread_list) >= self.threads:
                for th in thread_list:
                    th.join(timeout=10)
                thread_list = []

        for th in thread_list:
            th.join(timeout=10)

        elapsed = round(time.time() - start_time, 2)

        # Report
        print(Colors.info("\n" + "=" * 70))
        print(Colors.info("ADMIN PANEL SCAN REPORT"))
        print(Colors.info("=" * 70))
        print(Colors.info(
            f"Target: {self.target_url}"
        ))
        print(Colors.info(
            f"Checked: {self.checked}/{self.total}"
        ))
        print(Colors.info(f"Time: {elapsed}s"))

        if self.found:
            login_pages = [
                f for f in self.found
                if f['type'] == 'LOGIN PAGE'
            ]
            other_pages = [
                f for f in self.found
                if f['type'] != 'LOGIN PAGE'
            ]

            if login_pages:
                print(Colors.error(
                    f"\n🔑 LOGIN PAGES FOUND: "
                    f"{len(login_pages)}"
                ))
                for p in login_pages:
                    print(
                        f"  {Colors.GREEN}★"
                        f"{Colors.RESET} {p['url']}"
                    )

            if other_pages:
                print(Colors.info(
                    f"\n📁 Other Accessible: "
                    f"{len(other_pages)}"
                ))
                for p in other_pages:
                    print(
                        f"  [{p['status']}] "
                        f"{p['url']} "
                        f"[{p['type']}]"
                    )

            # Save
            save = input(
                Colors.input_prompt(
                    "\nSave results? [y/N]: "
                )
            ).strip().lower()
            if save == 'y':
                domain = self.web.extract_domain(
                    self.target_url
                )
                fname = f"admin_panels_{domain}.txt"
                with open(fname, 'w') as f:
                    for p in self.found:
                        f.write(
                            f"[{p['status']}] "
                            f"{p['url']} "
                            f"[{p['type']}]\n"
                        )
                print(Colors.success(
                    f"Saved to {fname}"
                ))
        else:
            print(Colors.success(
                "\n✅ No admin panels found."
            ))


def run():
    finder = AdminFinder()
    finder.run()
