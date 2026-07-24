# ============================================
# TermuxX v3.0 - Directory Bruteforcer
# Hidden directories aur files dhundhta hai
# Author: You
# ============================================

import threading
import time
import os
from core.colors import Colors
from core.web_engine import WebEngine


class DirBruteforcer:
    """
    Directory & File Bruteforcer
    Hidden paths discover karta hai
    """

    def __init__(self):
        self.web = WebEngine()
        self.target_url = None
        self.wordlist_path = "data/wordlists/directories.txt"
        self.extensions = ['', '.php', '.html', '.txt',
                           '.bak', '.old', '.zip']
        self.threads = 30
        self.found = []
        self.lock = threading.Lock()
        self.checked = 0
        self.total = 0

    def configure(self):
        """Settings"""
        print(Colors.info(
            "=== DIRECTORY BRUTEFORCER ===\n"
        ))

        url = input(
            Colors.input_prompt("Target URL: ")
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

        ext = input(
            Colors.input_prompt(
                "Extensions (comma separated, "
                "e.g., .php,.html,.bak) or ENTER "
                "for default: "
            )
        ).strip()
        if ext:
            self.extensions = [
                e.strip() for e in ext.split(',')
            ]
            self.extensions.insert(0, '')

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

    def check_dir(self, path):
        """Ek directory/file check karta hai"""
        url = f"{self.target_url}/{path}"
        resp = self.web.get(url, follow=False)

        with self.lock:
            self.checked += 1

        if resp and resp.status_code in [
            200, 201, 301, 302, 307, 401, 403
        ]:
            code = resp.status_code
            length = len(resp.text)

            # Skip too small 200 responses
            # (custom 404 pages)
            if code == 200 and length < 100:
                return

            status_map = {
                200: ("FOUND", Colors.GREEN),
                201: ("CREATED", Colors.GREEN),
                301: ("REDIRECT", Colors.YELLOW),
                302: ("REDIRECT", Colors.YELLOW),
                307: ("REDIRECT", Colors.YELLOW),
                401: ("AUTH REQUIRED", Colors.PURPLE),
                403: ("FORBIDDEN", Colors.RED),
            }
            status_text, color = status_map.get(
                code, ("UNKNOWN", Colors.WHITE)
            )

            with self.lock:
                self.found.append({
                    'path': path,
                    'url': url,
                    'status': code,
                    'type': status_text,
                    'length': length
                })
                print(
                    f"  {color}[{code}]"
                    f"{Colors.RESET} "
                    f"/{path:<50} "
                    f"[{status_text}] "
                    f"Size: {length}"
                )

    def run(self):
        """Bruteforcer start"""
        if not self.configure():
            return

        # Load wordlist
        if os.path.exists(self.wordlist_path):
            words = self.web.load_wordlist(
                self.wordlist_path
            )
        else:
            print(Colors.warning(
                "Using built-in directory list..."
            ))
            words = [
                "images", "css", "js", "admin", "api",
                "upload", "uploads", "backup", "config",
                "test", "dev", "old", "new", "tmp",
                "logs", "data", "files", "private",
                "public", "assets", "static", "media",
                "doc", "docs", "include", "lib",
                "cgi-bin", "scripts", "vendor",
                ".git", ".env", "robots.txt",
                "sitemap.xml", ".htaccess",
            ]

        # Generate paths with extensions
        all_paths = []
        for word in words:
            for ext in self.extensions:
                all_paths.append(f"{word}{ext}")

        self.total = len(all_paths)

        print(Colors.info(
            f"\nTarget: {self.target_url}"
        ))
        print(Colors.info(
            f"Paths: {self.total}"
        ))
        print(Colors.info(
            f"Extensions: {self.extensions}"
        ))
        print(Colors.info(
            f"Threads: {self.threads}"
        ))
        print(Colors.info("=" * 70))

        start_time = time.time()
        thread_list = []

        for path in all_paths:
            t = threading.Thread(
                target=self.check_dir,
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
        print(Colors.info("DIRECTORY SCAN REPORT"))
        print(Colors.info("=" * 70))
        print(Colors.info(
            f"Checked: {self.checked}/{self.total}"
        ))
        print(Colors.info(f"Time: {elapsed}s"))
        print(Colors.success(
            f"Found: {len(self.found)} paths"
        ))

        if self.found:
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
                fname = f"directories_{domain}.txt"
                with open(fname, 'w') as f:
                    for d in self.found:
                        f.write(
                            f"[{d['status']}] "
                            f"{d['url']}\n"
                        )
                print(Colors.success(
                    f"Saved to {fname}"
                ))


def run():
    bruter = DirBruteforcer()
    bruter.run()
