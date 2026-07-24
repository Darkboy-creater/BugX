# ============================================
# TermuxX v3.0 - Security Header Checker
# HTTP security headers analyze karta hai
# Author: You
# ============================================

from core.colors import Colors
from core.web_engine import WebEngine


SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'desc': 'HTTPS enforce karta hai (HSTS)',
        'severity': 'HIGH',
        'fix': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
    },
    'Content-Security-Policy': {
        'desc': 'XSS aur injection attacks se bachata hai',
        'severity': 'HIGH',
        'fix': "Add: Content-Security-Policy: default-src 'self'"
    },
    'X-Content-Type-Options': {
        'desc': 'MIME sniffing attacks rokta hai',
        'severity': 'MEDIUM',
        'fix': 'Add: X-Content-Type-Options: nosniff'
    },
    'X-Frame-Options': {
        'desc': 'Clickjacking se bachata hai',
        'severity': 'MEDIUM',
        'fix': 'Add: X-Frame-Options: DENY'
    },
    'X-XSS-Protection': {
        'desc': 'Browser XSS filter enable karta hai',
        'severity': 'LOW',
        'fix': 'Add: X-XSS-Protection: 1; mode=block'
    },
    'Referrer-Policy': {
        'desc': 'Referrer info ko control karta hai',
        'severity': 'LOW',
        'fix': 'Add: Referrer-Policy: strict-origin-when-cross-origin'
    },
    'Permissions-Policy': {
        'desc': 'Browser features control karta hai',
        'severity': 'LOW',
        'fix': 'Add: Permissions-Policy: camera=(), microphone=()'
    },
    'X-Permitted-Cross-Domain-Policies': {
        'desc': 'Flash/PDF cross domain policy',
        'severity': 'LOW',
        'fix': 'Add: X-Permitted-Cross-Domain-Policies: none'
    },
}

INFO_HEADERS = [
    'Server', 'X-Powered-By', 'X-AspNet-Version',
    'X-AspNetMvc-Version', 'X-Generator',
    'X-Drupal-Cache', 'X-Varnish',
    'Via', 'X-Backend-Server',
]


class HeaderChecker:
    """Security Headers Analyzer"""

    def __init__(self):
        self.web = WebEngine()
        self.target_url = None

    def configure(self):
        print(Colors.info(
            "=== SECURITY HEADER CHECKER ===\n"
        ))

        url = input(
            Colors.input_prompt("Target URL: ")
        ).strip()
        if not url:
            print(Colors.error("URL zaroori hai!"))
            return False
        self.target_url = self.web.normalize_url(url)
        return True

    def run(self):
        if not self.configure():
            return

        print(Colors.info(
            f"\nChecking: {self.target_url}"
        ))
        print(Colors.info("=" * 65))

        resp = self.web.get(self.target_url)
        if not resp:
            print(Colors.error("Cannot reach target!"))
            return

        headers = resp.headers
        missing = []
        present = []
        score = 0
        max_score = len(SECURITY_HEADERS)

        # Security headers check
        print(Colors.info(
            "\n--- SECURITY HEADERS ---\n"
        ))

        for header, info in SECURITY_HEADERS.items():
            if header in headers:
                score += 1
                present.append(header)
                print(
                    f"  {Colors.GREEN}[✓]{Colors.RESET} "
                    f"{header}: "
                    f"{headers[header][:60]}"
                )
            else:
                missing.append({
                    'header': header,
                    'info': info
                })
                sev_color = Colors.RED
                if info['severity'] == 'MEDIUM':
                    sev_color = Colors.YELLOW
                elif info['severity'] == 'LOW':
                    sev_color = Colors.CYAN
                print(
                    f"  {Colors.RED}[✗]{Colors.RESET} "
                    f"{header} "
                    f"{sev_color}"
                    f"[{info['severity']}]"
                    f"{Colors.RESET} "
                    f"- {info['desc']}"
                )

        # Info leaking headers
        print(Colors.info(
            "\n--- INFORMATION DISCLOSURE ---\n"
        ))
        info_found = False
        for header in INFO_HEADERS:
            if header in headers:
                info_found = True
                print(
                    f"  {Colors.YELLOW}[!]{Colors.RESET} "
                    f"{header}: {headers[header]} "
                    f"(Should be removed)"
                )
        if not info_found:
            print(Colors.success(
                "  No info-leaking headers found"
            ))

        # Score
        pct = round((score / max_score) * 100)
        grade_color = Colors.RED
        grade = "F"
        if pct >= 90:
            grade_color = Colors.GREEN
            grade = "A"
        elif pct >= 70:
            grade_color = Colors.GREEN
            grade = "B"
        elif pct >= 50:
            grade_color = Colors.YELLOW
            grade = "C"
        elif pct >= 30:
            grade_color = Colors.YELLOW
            grade = "D"

        print(Colors.info("\n" + "=" * 65))
        print(
            f"  Security Score: "
            f"{grade_color}{pct}% "
            f"(Grade: {grade}){Colors.RESET}"
        )
        print(
            f"  Present: {Colors.GREEN}"
            f"{score}{Colors.RESET} / "
            f"{max_score}"
        )
        print(
            f"  Missing: {Colors.RED}"
            f"{len(missing)}{Colors.RESET}"
        )

        # Fixes
        if missing:
            print(Colors.info(
                "\n--- RECOMMENDED FIXES ---\n"
            ))
            for m in missing:
                print(
                    f"  {Colors.YELLOW}→"
                    f"{Colors.RESET} "
                    f"{m['info']['fix']}"
                )


def run():
    checker = HeaderChecker()
    checker.run()
