# ============================================
# TermuxX v3.0 - CMS Detector
# WordPress, Joomla, Drupal etc. detect
# Author: You
# ============================================

import re
from core.colors import Colors
from core.web_engine import WebEngine


CMS_SIGNATURES = {
    'WordPress': {
        'paths': [
            '/wp-login.php', '/wp-admin/',
            '/wp-content/', '/wp-includes/',
            '/xmlrpc.php', '/wp-json/',
        ],
        'html': [
            'wp-content', 'wp-includes',
            'wordpress', 'wp-json',
        ],
        'headers': {'X-Powered-By': 'WordPress'},
        'meta': 'WordPress',
    },
    'Joomla': {
        'paths': [
            '/administrator/', '/components/',
            '/modules/', '/templates/',
            '/configuration.php',
        ],
        'html': [
            'joomla', '/administrator/',
            'com_content',
        ],
        'headers': {},
        'meta': 'Joomla',
    },
    'Drupal': {
        'paths': [
            '/core/misc/drupal.js',
            '/sites/default/', '/core/',
            '/modules/', '/user/login',
        ],
        'html': [
            'drupal', 'sites/default',
            'Drupal.settings',
        ],
        'headers': {
            'X-Generator': 'Drupal',
            'X-Drupal-Cache': ''
        },
        'meta': 'Drupal',
    },
    'Magento': {
        'paths': [
            '/skin/frontend/', '/js/mage/',
            '/app/etc/local.xml',
            '/admin/', '/downloader/',
        ],
        'html': [
            'magento', 'mage/', 'varien',
        ],
        'headers': {},
        'meta': 'Magento',
    },
    'Shopify': {
        'paths': [],
        'html': [
            'shopify', 'cdn.shopify.com',
            'myshopify',
        ],
        'headers': {
            'X-ShopId': '', 'X-Sorting-Hat-ShopId': ''
        },
        'meta': 'Shopify',
    },
    'Laravel': {
        'paths': [],
        'html': ['laravel', 'csrf-token'],
        'headers': {},
        'meta': 'Laravel',
        'cookies': ['laravel_session', 'XSRF-TOKEN'],
    },
    'Django': {
        'paths': ['/admin/'],
        'html': [
            'csrfmiddlewaretoken', 'django',
        ],
        'headers': {},
        'meta': 'Django',
        'cookies': ['csrftoken', 'sessionid'],
    },
}


class CMSDetector:
    """CMS Detection Engine"""

    def __init__(self):
        self.web = WebEngine()
        self.target_url = None
        self.detected = []

    def configure(self):
        print(Colors.info(
            "=== CMS DETECTOR ===\n"
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
            f"\nScanning: {self.target_url}"
        ))
        print(Colors.info("=" * 60))

        resp = self.web.get(self.target_url)
        if not resp:
            print(Colors.error("Cannot reach target!"))
            return

        html_text = resp.text.lower()
        headers = resp.headers
        cookies = resp.cookies

        for cms, sigs in CMS_SIGNATURES.items():
            confidence = 0
            evidence = []

            # HTML check
            for pattern in sigs.get('html', []):
                if pattern.lower() in html_text:
                    confidence += 25
                    evidence.append(
                        f"HTML: '{pattern}' found"
                    )

            # Path check
            for path in sigs.get('paths', []):
                check_url = f"{self.target_url}{path}"
                path_resp = self.web.head(check_url)
                if path_resp and path_resp.status_code in [
                    200, 301, 302, 403
                ]:
                    confidence += 30
                    evidence.append(
                        f"Path: {path} "
                        f"[{path_resp.status_code}]"
                    )

            # Header check
            for h_name, h_val in sigs.get(
                'headers', {}
            ).items():
                if h_name in headers:
                    if (not h_val or
                            h_val in headers[h_name]):
                        confidence += 40
                        evidence.append(
                            f"Header: {h_name}"
                        )

            # Cookie check
            for cookie in sigs.get('cookies', []):
                if cookie in cookies:
                    confidence += 35
                    evidence.append(
                        f"Cookie: {cookie}"
                    )

            # Meta tag check
            meta_pattern = sigs.get('meta', '')
            if meta_pattern:
                meta_found = re.search(
                    f'<meta[^>]*{meta_pattern.lower()}',
                    html_text
                )
                if meta_found:
                    confidence += 30
                    evidence.append("Meta tag found")

            if confidence > 0:
                confidence = min(confidence, 100)
                self.detected.append({
                    'cms': cms,
                    'confidence': confidence,
                    'evidence': evidence
                })

        # Report
        print(Colors.info("\n" + "=" * 60))
        print(Colors.info("CMS DETECTION REPORT"))
        print(Colors.info("=" * 60))

        if self.detected:
            sorted_cms = sorted(
                self.detected,
                key=lambda x: x['confidence'],
                reverse=True
            )
            for det in sorted_cms:
                conf = det['confidence']
                conf_color = Colors.GREEN
                if conf < 50:
                    conf_color = Colors.YELLOW
                if conf < 25:
                    conf_color = Colors.RED

                print(
                    f"\n  {Colors.CYAN}"
                    f"{det['cms']}{Colors.RESET} "
                    f"- Confidence: "
                    f"{conf_color}{conf}%"
                    f"{Colors.RESET}"
                )
                for ev in det['evidence']:
                    print(
                        f"    → {ev}"
                    )
        else:
            print(Colors.warning(
                "\nNo known CMS detected."
            ))

        # Server info
        server = headers.get('Server', 'Unknown')
        powered = headers.get(
            'X-Powered-By', 'Unknown'
        )
        print(Colors.info(
            f"\n  Server: {server}"
        ))
        print(Colors.info(
            f"  X-Powered-By: {powered}"
        ))


def run():
    detector = CMSDetector()
    detector.run()
