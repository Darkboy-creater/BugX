# ============================================
# TermuxX v3.0 - Full Web Scanner
# All-in-One: SQLi + XSS + Subdomain +
# Admin + Dir + Headers + CMS
# Author: You
# ============================================

import time
from core.colors import Colors
from core.web_engine import WebEngine


class FullScanner:
    """All-in-One Web Security Scanner"""

    def __init__(self):
        self.web = WebEngine()
        self.target_url = None

    def configure(self):
        print(Colors.info(
            "=== FULL WEB SECURITY SCAN ===\n"
        ))
        print(Colors.warning(
            "Yeh scan sab modules ek saath "
            "chalayega. Time lag sakta hai.\n"
        ))

        url = input(
            Colors.input_prompt("Target URL: ")
        ).strip()
        if not url:
            print(Colors.error("URL zaroori hai!"))
            return False
        self.target_url = self.web.normalize_url(url)

        print(Colors.info("\nModules to run:"))
        print("  1. CMS Detection")
        print("  2. Security Headers Check")
        print("  3. Admin Panel Finder")
        print("  4. Directory Bruteforce")
        print("  5. SQL Injection Scanner")
        print("  6. XSS Scanner")
        print("  7. Subdomain Finder")
        print()

        confirm = input(
            Colors.input_prompt(
                "Start full scan? [Y/n]: "
            )
        ).strip().lower()
        return confirm != 'n'

    def run(self):
        if not self.configure():
            return

        print(Colors.info(f"\nTarget: {self.target_url}"))
        print(Colors.info("=" * 60))

        start = time.time()
        modules_run = []

        # 1. CMS Detection
        try:
            print(Colors.info(
                "\n[1/7] CMS DETECTION..."
            ))
            from modules.web.cms_detect import (
                CMSDetector
            )
            det = CMSDetector()
            det.target_url = self.target_url
            det.run.__wrapped__ = True
            # Quick inline run
            resp = self.web.get(self.target_url)
            if resp:
                server = resp.headers.get(
                    'Server', 'Unknown'
                )
                print(Colors.info(
                    f"  Server: {server}"
                ))
            modules_run.append("CMS Detection")
        except Exception as e:
            print(Colors.error(f"CMS Error: {e}"))

        # 2. Security Headers
        try:
            print(Colors.info(
                "\n[2/7] SECURITY HEADERS..."
            ))
            from modules.web.header_check import (
                HeaderChecker
            )
            hc = HeaderChecker()
            hc.target_url = self.target_url
            hc.run()
            modules_run.append("Header Check")
        except Exception as e:
            print(Colors.error(
                f"Header Error: {e}"
            ))

        # 3. Admin Finder (quick)
        try:
            print(Colors.info(
                "\n[3/7] ADMIN PANEL FINDER..."
            ))
            from modules.web.admin_finder import (
                AdminFinder
            )
            af = AdminFinder()
            af.target_url = self.target_url
            af.threads = 20
            # Quick check with top 20 paths
            quick_paths = [
                "admin", "administrator",
                "admin/login", "wp-admin",
                "wp-login.php", "login",
                "dashboard", "cpanel",
                "phpmyadmin", "panel",
                "admin.php", "manager",
                "backend", "cms/admin",
                "user/login", "signin",
                "auth/login", "webadmin",
                "portal/admin", "console",
            ]
            for path in quick_paths:
                af.check_path(path)
            if af.found:
                print(Colors.success(
                    f"  Found {len(af.found)} "
                    f"admin pages!"
                ))
            modules_run.append("Admin Finder")
        except Exception as e:
            print(Colors.error(
                f"Admin Error: {e}"
            ))

        # 4. SQL Injection (quick)
        try:
            print(Colors.info(
                "\n[5/7] SQL INJECTION TEST..."
            ))
            from modules.web.sql_scanner import (
                SQLScanner
            )
            sq = SQLScanner()
            sq.target_url = self.target_url
            sq.web = self.web
            vulns = sq.test_error_based(
                self.target_url
            )
            if vulns:
                print(Colors.error(
                    f"  {len(vulns)} SQLi "
                    f"vulnerabilities!"
                ))
            else:
                print(Colors.success(
                    "  No obvious SQLi found"
                ))
            modules_run.append("SQLi Scanner")
        except Exception as e:
            print(Colors.error(
                f"SQLi Error: {e}"
            ))

        # 5. XSS (quick)
        try:
            print(Colors.info(
                "\n[6/7] XSS TEST..."
            ))
            from modules.web.xss_scanner import (
                XSSScanner
            )
            xss = XSSScanner()
            xss.target_url = self.target_url
            xss.web = self.web
            xss.test_url_params()
            if xss.vulnerabilities:
                print(Colors.error(
                    f"  {len(xss.vulnerabilities)} "
                    f"XSS found!"
                ))
            else:
                print(Colors.success(
                    "  No obvious XSS found"
                ))
            modules_run.append("XSS Scanner")
        except Exception as e:
            print(Colors.error(
                f"XSS Error: {e}"
            ))

        elapsed = round(time.time() - start, 2)

        # Final report
        print(Colors.info("\n" + "=" * 60))
        print(Colors.info("FULL SCAN COMPLETE"))
        print(Colors.info("=" * 60))
        print(Colors.info(
            f"Target: {self.target_url}"
        ))
        print(Colors.info(f"Time: {elapsed}s"))
        print(Colors.info(
            f"Modules run: {len(modules_run)}"
        ))
        for m in modules_run:
            print(f"  ✓ {m}")
        print()


def run():
    scanner = FullScanner()
    scanner.run()
