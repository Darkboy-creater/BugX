# ============================================
# TermuxX v3.0 - Subdomain Finder
# DNS Brute Force + Threading
# Author: You
# ============================================

import socket
import threading
import time
import os
from core.colors import Colors
from core.web_engine import WebEngine


class SubdomainFinder:
    """
    Fast Subdomain Finder
    DNS resolution + multi-threading
    """

    def __init__(self):
        self.web = WebEngine()
        self.domain = None
        self.wordlist_path = "data/wordlists/subdomains.txt"
        self.threads = 50
        self.found = []
        self.lock = threading.Lock()
        self.total = 0
        self.checked = 0

    def configure(self):
        """Settings"""
        print(Colors.info(
            "=== SUBDOMAIN FINDER ===\n"
        ))

        domain = input(
            Colors.input_prompt(
                "Target Domain (e.g., example.com): "
            )
        ).strip()
        if not domain:
            print(Colors.error("Domain zaroori hai!"))
            return False

        # Remove http/https
        domain = domain.replace("http://", "")
        domain = domain.replace("https://", "")
        domain = domain.replace("/", "")
        self.domain = domain

        # Wordlist
        wl = input(
            Colors.input_prompt(
                f"Wordlist path "
                f"(default: {self.wordlist_path}): "
            )
        ).strip()
        if wl:
            self.wordlist_path = wl

        # Threads
        th = input(
            Colors.input_prompt(
                "Threads (default 50): "
            )
        ).strip()
        if th:
            try:
                self.threads = int(th)
            except:
                pass

        return True

    def check_subdomain(self, subdomain):
        """Ek subdomain check karta hai"""
        full = f"{subdomain}.{self.domain}"
        try:
            ip = socket.gethostbyname(full)

            # HTTP check
            http_status = "N/A"
            try:
                resp = self.web.head(f"http://{full}")
                if resp:
                    http_status = str(resp.status_code)
            except:
                pass

            with self.lock:
                self.found.append({
                    'subdomain': full,
                    'ip': ip,
                    'http': http_status
                })
                print(
                    f"  {Colors.GREEN}[+]{Colors.RESET} "
                    f"{full:<40} "
                    f"IP: {ip:<16} "
                    f"HTTP: {http_status}"
                )
        except socket.gaierror:
            pass
        except:
            pass
        finally:
            with self.lock:
                self.checked += 1

    def run(self):
        """Finder start"""
        if not self.configure():
            return

        # Load wordlist
        if not os.path.exists(self.wordlist_path):
            print(Colors.error(
                f"Wordlist not found: {self.wordlist_path}"
            ))
            # Use built-in list
            print(Colors.warning(
                "Using built-in subdomain list..."
            ))
            subdomains = [
                "www", "mail", "ftp", "admin", "blog",
                "dev", "test", "staging", "api", "app",
                "m", "mobile", "shop", "store", "forum",
                "wiki", "docs", "support", "help",
                "portal", "vpn", "remote", "secure",
                "cdn", "media", "static", "assets",
                "upload", "cloud", "db", "mysql",
                "phpmyadmin", "cpanel", "webmail",
                "dashboard", "login", "git", "jenkins",
                "monitor", "status", "beta", "demo",
                "ns1", "ns2", "dns", "mx", "smtp", "pop",
                "imap", "ssh", "proxy",
            ]
        else:
            subdomains = self.web.load_wordlist(
                self.wordlist_path
            )

        self.total = len(subdomains)

        print(Colors.info(
            f"\nDomain: {self.domain}"
        ))
        print(Colors.info(
            f"Wordlist: {self.total} subdomains"
        ))
        print(Colors.info(
            f"Threads: {self.threads}"
        ))
        print(Colors.info("=" * 65))
        print(
            f"  {'SUBDOMAIN':<40}"
            f"{'IP':<18}{'HTTP'}"
        )
        print("  " + "-" * 60)

        start_time = time.time()
        thread_list = []

        for sub in subdomains:
            t = threading.Thread(
                target=self.check_subdomain,
                args=(sub,)
            )
            thread_list.append(t)
            t.start()

            if len(thread_list) >= self.threads:
                for th in thread_list:
                    th.join(timeout=5)
                thread_list = []

        for th in thread_list:
            th.join(timeout=5)

        elapsed = round(time.time() - start_time, 2)

        # Report
        print(Colors.info("\n" + "=" * 65))
        print(Colors.info("SUBDOMAIN SCAN REPORT"))
        print(Colors.info("=" * 65))
        print(Colors.info(f"Domain: {self.domain}"))
        print(Colors.info(
            f"Checked: {self.checked}/{self.total}"
        ))
        print(Colors.info(f"Time: {elapsed}s"))
        print(Colors.success(
            f"Found: {len(self.found)} subdomains"
        ))

        if self.found:
            print(Colors.info("\n--- RESULTS ---"))
            print(
                f"  {'SUBDOMAIN':<40}"
                f"{'IP':<18}{'HTTP'}"
            )
            print("  " + "-" * 60)
            for s in sorted(
                self.found,
                key=lambda x: x['subdomain']
            ):
                print(
                    f"  {Colors.GREEN}"
                    f"{s['subdomain']:<40}"
                    f"{Colors.RESET}"
                    f"{s['ip']:<18}"
                    f"{s['http']}"
                )

            # Save results
            save = input(
                Colors.input_prompt(
                    "\nSave results? [y/N]: "
                )
            ).strip().lower()
            if save == 'y':
                fname = f"subdomains_{self.domain}.txt"
                with open(fname, 'w') as f:
                    for s in self.found:
                        f.write(
                            f"{s['subdomain']},"
                            f"{s['ip']},"
                            f"{s['http']}\n"
                        )
                print(Colors.success(
                    f"Saved to {fname}"
                ))


def run():
    finder = SubdomainFinder()
    finder.run()
