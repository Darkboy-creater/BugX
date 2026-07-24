# ============================================
# TermuxX Framework v3.0 - Web Engine
# HTTP Request Engine for all web modules
# Author: You
# ============================================

import requests
import urllib3
import socket
import threading
import time
import re
from datetime import datetime
from core.colors import Colors

# SSL warnings suppress
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebEngine:
    """
    Core Web Engine
    Sabhi web modules isko use karenge
    HTTP requests, response parsing, threading
    """

    def __init__(self):
        self.timeout = 10
        self.max_threads = 50
        self.user_agents = [
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; "
                "rv:121.0) Gecko/20100101 Firefox/121.0"
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                "Version/17.2 Safari/605.1.15"
            ),
        ]
        self.current_ua = 0
        self.session = requests.Session()
        self.lock = threading.Lock()

    def get_headers(self):
        """Rotating User-Agent headers"""
        ua = self.user_agents[
            self.current_ua % len(self.user_agents)
        ]
        self.current_ua += 1
        return {
            "User-Agent": ua,
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }

    def get(self, url, params=None, follow=True):
        """GET request"""
        try:
            resp = self.session.get(
                url,
                params=params,
                headers=self.get_headers(),
                timeout=self.timeout,
                verify=False,
                allow_redirects=follow
            )
            return resp
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except Exception:
            return None

    def post(self, url, data=None, follow=True):
        """POST request"""
        try:
            resp = self.session.post(
                url,
                data=data,
                headers=self.get_headers(),
                timeout=self.timeout,
                verify=False,
                allow_redirects=follow
            )
            return resp
        except:
            return None

    def head(self, url):
        """HEAD request (fast check)"""
        try:
            resp = self.session.head(
                url,
                headers=self.get_headers(),
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            return resp
        except:
            return None

    def check_url(self, url):
        """URL accessible hai ya nahi"""
        resp = self.get(url)
        if resp and resp.status_code < 500:
            return True
        return False

    def normalize_url(self, url):
        """URL ko proper format mein laata hai"""
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        if url.endswith("/"):
            url = url[:-1]
        return url

    def extract_domain(self, url):
        """URL se domain extract karta hai"""
        url = self.normalize_url(url)
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc

    def extract_forms(self, url):
        """
        HTML page se forms extract karta hai
        SQL injection aur XSS testing ke liye
        """
        resp = self.get(url)
        if not resp:
            return []

        forms = []
        html = resp.text

        # Simple form parser (regex based)
        form_pattern = re.compile(
            r'<form[^>]*>(.*?)</form>',
            re.DOTALL | re.IGNORECASE
        )
        action_pattern = re.compile(
            r'action=["\']([^"\']*)["\']',
            re.IGNORECASE
        )
        method_pattern = re.compile(
            r'method=["\']([^"\']*)["\']',
            re.IGNORECASE
        )
        input_pattern = re.compile(
            r'<input[^>]*>',
            re.IGNORECASE
        )
        name_pattern = re.compile(
            r'name=["\']([^"\']*)["\']',
            re.IGNORECASE
        )
        type_pattern = re.compile(
            r'type=["\']([^"\']*)["\']',
            re.IGNORECASE
        )
        value_pattern = re.compile(
            r'value=["\']([^"\']*)["\']',
            re.IGNORECASE
        )
        textarea_pattern = re.compile(
            r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>',
            re.IGNORECASE
        )
        select_pattern = re.compile(
            r'<select[^>]*name=["\']([^"\']*)["\'][^>]*>',
            re.IGNORECASE
        )

        form_matches = form_pattern.findall(html)
        form_tags = re.findall(
            r'<form[^>]*>', html, re.IGNORECASE
        )

        for i, form_html in enumerate(form_matches):
            form_tag = (
                form_tags[i] if i < len(form_tags) else ""
            )

            # Action URL
            action_match = action_pattern.search(form_tag)
            action = (
                action_match.group(1)
                if action_match else url
            )

            # Method
            method_match = method_pattern.search(form_tag)
            method = (
                method_match.group(1).upper()
                if method_match else "GET"
            )

            # Input fields
            inputs = []
            for inp in input_pattern.findall(form_html):
                name_m = name_pattern.search(inp)
                type_m = type_pattern.search(inp)
                val_m = value_pattern.search(inp)

                if name_m:
                    inputs.append({
                        'name': name_m.group(1),
                        'type': (
                            type_m.group(1)
                            if type_m else "text"
                        ),
                        'value': (
                            val_m.group(1) if val_m else ""
                        )
                    })

            # Textarea fields
            for ta in textarea_pattern.findall(form_html):
                inputs.append({
                    'name': ta,
                    'type': 'textarea',
                    'value': ''
                })

            # Select fields
            for sel in select_pattern.findall(form_html):
                inputs.append({
                    'name': sel,
                    'type': 'select',
                    'value': ''
                })

            if inputs:
                forms.append({
                    'action': action,
                    'method': method,
                    'inputs': inputs
                })

        return forms

    def resolve_subdomain(self, subdomain, domain):
        """Subdomain resolve karta hai"""
        full = f"{subdomain}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            return {'subdomain': full, 'ip': ip}
        except socket.gaierror:
            return None

    def load_wordlist(self, filepath):
        """Wordlist file load karta hai"""
        words = []
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        words.append(line)
        except FileNotFoundError:
            print(Colors.error(
                f"Wordlist not found: {filepath}"
            ))
        return words
