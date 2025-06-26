import requests
import socket
import json
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup  # pip install beautifulsoup4
import threading

class WebScanner:
    def __init__(self, target):
        self.target = target if target.startswith("http") else "http://" + target
        self.hostname = urlparse(self.target).netloc
        self.results = {
            "open_ports": [],
            "missing_security_headers": [],
            "detected_cms": [],
            "sql_injection": False,
            "xss_vulnerability": False,
            "admin_bruteforce": None,
            "known_cves": [],
            "found_urls": [],
        }
        self.session = requests.Session()

    def scan_ports(self, ports=[80, 443, 8080, 8443]):
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.hostname, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        self.results["open_ports"] = open_ports
        print(f"[+] Open ports: {open_ports}")

    def check_security_headers(self):
        try:
            resp = self.session.get(self.target)
            headers = resp.headers
            sec_headers = ["Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"]
            missing = [h for h in sec_headers if h not in headers]
            self.results["missing_security_headers"] = missing
            print(f"[+] Missing security headers: {missing}")
        except Exception as e:
            print(f"[-] Error checking headers: {e}")

    def detect_cms(self):
        cms_signatures = {
            "WordPress": ["wp-content", "wp-includes"],
            "Joomla": ["Joomla!", "index.php?option=com"],
            "Drupal": ["sites/default/files", "drupal.js"]
        }
        try:
            resp = self.session.get(self.target)
            content = resp.text.lower()
            detected = []
            for cms, signatures in cms_signatures.items():
                if any(sig.lower() in content for sig in signatures):
                    detected.append(cms)
            self.results["detected_cms"] = detected
            print(f"[+] Detected CMS: {detected if detected else 'None'}")
        except Exception as e:
            print(f"[-] Error detecting CMS: {e}")

    def test_sql_injection(self):
        test_url = urljoin(self.target, "?id=1'")
        try:
            resp = self.session.get(test_url)
            errors = ["you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark", "sql syntax error"]
            if any(err in resp.text.lower() for err in errors):
                self.results["sql_injection"] = True
                print("[!] Possible SQL Injection vulnerability detected!")
            else:
                print("[+] No SQL Injection vulnerability detected.")
        except Exception as e:
            print(f"[-] Error testing SQL injection: {e}")

    def test_xss(self):
        xss_payload = "<script>alert('XSS')</script>"
        test_url = urljoin(self.target, f"?q={xss_payload}")
        try:
            resp = self.session.get(test_url)
            if xss_payload in resp.text:
                self.results["xss_vulnerability"] = True
                print("[!] Possible XSS vulnerability detected!")
            else:
                print("[+] No XSS vulnerability detected.")
        except Exception as e:
            print(f"[-] Error testing XSS: {e}")

    def brute_force_admin(self):
        # Simple brute force on /admin/login or /admin with basic creds
        urls_to_try = [urljoin(self.target, path) for path in ["/admin", "/admin/login", "/administrator"]]
        creds = [("admin", "admin"), ("admin", "password"), ("admin", "123456"), ("root", "toor")]

        def try_login(url, user, pwd):
            try:
                resp = self.session.post(url, data={"username": user, "password": pwd}, timeout=3)
                # Simplification : si code 200 et pas "login" dans la page => succès
                if resp.status_code == 200 and "login" not in resp.text.lower():
                    return True
            except:
                return False
            return False

        for url in urls_to_try:
            for user, pwd in creds:
                print(f"[+] Trying {user}:{pwd} on {url}")
                if try_login(url, user, pwd):
                    self.results["admin_bruteforce"] = {"url": url, "username": user, "password": pwd}
                    print(f"[!] Admin login found: {user}:{pwd} at {url}")
                    return
        print("[+] Admin brute force finished: no valid creds found.")

    def scan_cves(self):
        # Dictionnaire simplifié d'exemples CVE par CMS/version (mock)
        cve_db = {
            "WordPress": ["CVE-2020-12345", "CVE-2019-54321"],
            "Joomla": ["CVE-2018-11111"],
            "Drupal": ["CVE-2017-22222"],
        }
        detected_cves = []
        for cms in self.results.get("detected_cms", []):
            detected_cves.extend(cve_db.get(cms, []))
        self.results["known_cves"] = detected_cves
        if detected_cves:
            print(f"[!] Known CVEs detected for CMS: {detected_cves}")
        else:
            print("[+] No known CVEs detected.")

    def crawl_urls(self, max_urls=20):
        to_visit = set([self.target])
        visited = set()
        found_urls = []

        while to_visit and len(visited) < max_urls:
            url = to_visit.pop()
            try:
                resp = self.session.get(url, timeout=3)
                visited.add(url)
                found_urls.append(url)

                soup = BeautifulSoup(resp.text, "html.parser")
                for link in soup.find_all("a", href=True):
                    href = link['href']
                    if href.startswith("/"):
                        full_url = urljoin(self.target, href)
                    elif href.startswith(self.target):
                        full_url = href
                    else:
                        continue
                    if full_url not in visited and full_url not in to_visit:
                        to_visit.add(full_url)
            except Exception as e:
                print(f"[-] Error crawling {url}: {e}")
                visited.add(url)

        self.results["found_urls"] = found_urls
        print(f"[+] Crawled URLs ({len(found_urls)}):")
        for u in found_urls:
            print(f"  - {u}")

    def generate_report_json(self):
        with open("scan_report.json", "w") as f:
            json.dump(self.results, f, indent=4)
        print("[+] JSON report saved as scan_report.json")

    def generate_report_html(self):
        html_content = f"""
        <html><head><title>Scan Report</title></head><body>
        <h1>Scan Report for {self.target}</h1>
        <h2>Open Ports</h2>
        <p>{self.results['open_ports']}</p>
        <h2>Missing Security Headers</h2>
        <p>{self.results['missing_security_headers']}</p>
        <h2>Detected CMS</h2>
        <p>{', '.join(self.results['detected_cms']) if self.results['detected_cms'] else 'None'}</p>
        <h2>SQL Injection Vulnerability</h2>
        <p>{'Yes' if self.results['sql_injection'] else 'No'}</p>
        <h2>XSS Vulnerability</h2>
        <p>{'Yes' if self.results['xss_vulnerability'] else 'No'}</p>
        <h2>Admin Brute Force Result</h2>
        <p>{self.results['admin_bruteforce'] if self.results['admin_bruteforce'] else 'No valid credentials found'}</p>
        <h2>Known CVEs</h2>
        <p>{', '.join(self.results['known_cves']) if self.results['known_cves'] else 'None'}</p>
        <h2>Crawled URLs</h2>
        <ul>
        {''.join(f'<li>{url}</li>' for url in self.results['found_urls'])}
        </ul>
        </body></html>
        """
        with open("scan_report.html", "w") as f:
            f.write(html_content)
        print("[+] HTML report saved as scan_report.html")

    def run_all(self):
        self.scan_ports()
        self.check_security_headers()
        self.detect_cms()
        self.test_sql_injection()
        self.test_xss()
        self.brute_force_admin()
        self.scan_cves()
        self.crawl_urls()
        self.generate_report_json()
        self.generate_report_html()

if __name__ == "__main__":
    print("=== Ethical Web Scanner ===")
    target = input("Enter target URL or IP: ").strip()
    scanner = WebScanner(target)
    scanner.run_all()
