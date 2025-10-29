#!/usr/bin/env python3
"""
Advanced Subdomain Buster + Full-Site Crawler + Screenshots + IP Lookup
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Set, List, Dict, Optional
from urllib.parse import urlparse, urljoin

import aiohttp
from aiohttp import ClientSession, TCPConnector
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from robotexclusionrulesparser import RobotExclusionRulesParser
import dns.resolver
from playwright.async_api import async_playwright

# --------------------------------------------------------------
# Configuration
# --------------------------------------------------------------
init(autoreset=True)

WORDLIST = [
    "www", "api", "dev", "test", "staging", "admin", "mail", "ftp",
    "blog", "shop", "store", "app", "beta", "secure", "login", "panel",
    "dashboard", "cpanel", "webmail", "vpn", "remote", "gateway",
    # === CORE & COMMON (1–40) ===
    'www', 'api', 'app', 'auth', 'admin', 'dashboard', 'blog', 'image', 'cdn', 'static',
    'dev', 'test', 'staging', 'prod', 'beta', 'mail', 'webmail', 'ftp', 'db', 'mysql',
    'redis', 'mongo', 'ns1', 'ns2', 'mx', 'smtp', 'login', 'secure', 'portal', 'vpn',
    'backup', 'logs', 'monitor', 'status', 'health', 'metrics', 'grafana', 'kibana',
    'jenkins', 'gitlab', 'docker', 'k8s', 'prometheus', 'elastic', 'console', 'panel',

    # === API & MICROSERVICES (41–70) ===
    'api2', 'api3', 'v1', 'v2', 'v3', 'graphql', 'rest', 'rpc', 'gateway', 'proxy',
    'edge', 'authz', 'oauth', 'openid', 'sso', 'identity', 'users', 'accounts', 'billing',
    'payments', 'orders', 'cart', 'checkout', 'search', 'recommend', 'catalog', 'inventory',
    'warehouse', 'shipping', 'tracking', 'notifications', 'events', 'webhook', 'callback',
    'worker', 'queue', 'jobs', 'tasks', 'scheduler', 'cron', 'batch', 'import', 'export',

    # === INFRA & DEVOPS (71–100) ===
    'ci', 'cd', 'build', 'deploy', 'release', 'registry', 'harbor', 'nexus', 'artifactory',
    'sonarqube', 'sonar', 'code', 'repo', 'repos', 'source', 'git', 'svn', 'hg', 'bitbucket',
    'perforce', 'vault', 'secrets', 'config', 'cfg', 'env', 'configserver', 'eureka', 'consul',
    'zookeeper', 'etcd', 'kafka', 'rabbitmq', 'nats', 'pulsar', 'activemq', 'broker', 'pubsub',
    'cache', 'memcached', 'varnish', 'nginx', 'traefik', 'haproxy', 'lb', 'loadbalancer', 'ingress',

    # === MONITORING & OBSERVABILITY (101–120) ===
    'alert', 'alerts', 'alertmanager', 'uptime', 'ping', 'probe', 'blackbox', 'loki', 'tempo',
    'jaeger', 'zipkin', 'trace', 'tracing', 'opentelemetry', 'otel', 'sentry', 'datadog', 'newrelic',
    'dynatrace', 'appdynamics', 'log', 'logstash', 'fluentd', 'syslog', 'splunk', 'sumologic',

    # === SECURITY & COMPLIANCE (121–140) ===
    'sec', 'security', 'waf', 'firewall', 'ids', 'ips', 'scan', 'scanner', 'nessus', 'qualys',
    'burp', 'zaproxy', 'owasp', 'csp', 'hsts', 'ssl', 'tls', 'cert', 'certificate', 'pki',
    'ca', 'rootca', 'iam', 'policy', 'audit', 'compliance', 'gdpr', 'hipaa', 'soc2', 'iso27001',

    # === BUSINESS & MARKETING (141–160) ===
    'shop', 'store', 'ecommerce', 'market', 'marketing', 'campaign', 'ads', 'adwords', 'analytics',
    'ga', 'tagmanager', 'gtm', 'pixel', 'crm', 'sales', 'support', 'help', 'kb', 'docs',
    'wiki', 'forum', 'community', 'press', 'news', 'media', 'assets', 'files', 'download', 'upload',

    # === LEGACY & MISC (161–180) ===
    'old', 'legacy', 'archive', 'demo', 'sandbox', 'playground', 'lab', 'labs', 'research', 'devops',
    'internal', 'private', 'corp', 'intranet', 'extranet', 'partner', 'vendor', 'client', 'customer',
    'employee', 'hr', 'payroll', 'finance', 'accounting', 'legal', 'it', 'noc', 'soc', 'helpdesk',

    # === CLOUDS & CDNs (181–200) ===
    'aws', 'gcp', 'azure', 'cloud', 'cloudfront', 'akamai', 'fastly', 'cloudflare', 'imperva', 'incapsula',
    's3', 'storage', 'bucket', 'blob', 'fileserver', 'nfs', 'cifs', 'share', 'sync', 'backup1',
    'backup2', 'dr', 'disaster', 'recovery', 'replica', 'mirror', 'failover', 'lb1', 'lb2', 'node1',

    # === DATABASE & CACHING (201–220) ===
    'postgres', 'postgresql', 'psql', 'oracle', 'mssql', 'sqlserver', 'cassandra', 'couchbase', 'dynamodb',
    'bigtable', 'spanner', 'aurora', 'rds', 'atlas', 'cosmos', 'influx', 'timeseries', 'tsdb', 'graph',
    'neo4j', 'arangodb', 'dgraph', 'janus', 'titan', 'orientdb', 'couchdb', 'riak', 'hbase', 'hadoop',

    # === MESSAGING & STREAMING (221–240) ===
    'stream', 'streams', 'ingest', 'realtime', 'rt', 'ws', 'websocket', 'socket', 'mqtt', 'amqp',
    'stomp', 'redis-pubsub', 'kafka-connect', 'flink', 'spark', 'storm', 'heron', 'samza', 'kinesis',
    'firehose', 'pubsub', 'eventhub', 'servicebus', 'sqs', 'sns', 'cloudwatch', 'cloudtrail', 'guardduty',

    # === TESTING & QA (241–250) ===
    'qa', 'uat', 'integration', 'e2e', 'perf', 'load', 'stress', 'smoke', 'canary', 'feature',

    "mail",          "webmail",       "smtp",          "imap",
    "pop",           "pop3",          "mail2",         "mx",
    "mx1",           "mx2",           "email",         "inbound",
    "outbound",      "relay",         "mailrelay",     "postfix",
    "exim",          "sendmail",      "mailgate",      "gateway",
    "mailgw",        "mailhost",      "mailserver",    "mail-srv",
    "mail01",        "mail02",        "mail03",        "mail04",
    "mail05",        "mailadmin",     "webmail2",      "securemail",
    "secmail",       "smail",         "mailbox",       "mbox",
    "maildrop",      "mailin",        "mailout",       "mailhub",
    "mailrouter",    "mailproxy",     "mailfilter",    "spam",
    "antispam",      "mailscan",      "mailguard",     "mailwall",
    "mailfront",     "mailback",      "mailarchive",   "archive",

    # === Admin & Management ===
    "admin",          "adminer",       "cpanel",        "whm",
    "webadmin",       "panel",         "dashboard",     "manage",
    "control",        "portal",        "myaccount",     "account",

    # === API & Developer ===
    "api",            "api2",          "dev",           "developer",
    "staging",        "test",          "beta",          "sandbox",
    "graphql",        "rest",          "v1",            "v2",

    # === Databases & Backends ===
    "db",             "mysql",         "postgres",      "mongodb",
    "redis",          "elastic",       "elasticsearch", "couchdb",
    "influxdb",       "prometheus",    "grafana",       "kibana",

    # === Cloud & Storage ===
    "cloud",          "storage",       "s3",            "bucket",
    "cdn",            "static",        "assets",        "files",
    "upload",         "download",      "share",         "ftp",

    # === Monitoring & Logs ===
    "monitor",        "status",        "health",        "uptime",
    "logs",           "log",           "metrics",       "stats",
    "nagios",         "zabbix",        "splunk",        "graylog",

    # === Remote Access & Tools ===
    "remote",         "vpn",           "ssh",           "bastion",
    "jump",           "gateway",       "proxy",         "reverse-proxy",

    # === Security & Auth ===
    "auth",           "login",         "signin",        "sso",
    "oauth",          "openid",        "secure",        "vault",

    # === Miscellaneous Services ===
    "internal",       "intranet",      "legacy",        "old",
    "backup",         "archive",       "repo",          "git",
    "jenkins",        "ci",            "cd",            "build",
    "docker",         "k8s",           "kubernetes",    "cluster"
]

MAX_CONCURRENT = 100
REQUEST_DELAY = 0.1
TIMEOUT = aiohttp.ClientTimeout(total=20)
USER_AGENT = "SubX-Crawler/2.0 (+https://github.com/yourname/subx)"

# --------------------------------------------------------------
# Colored Output
# --------------------------------------------------------------
def print_green(txt):   print(f"{Fore.GREEN}{txt}{Style.RESET_ALL}")
def print_cyan(txt):    print(f"{Fore.CYAN}{txt}{Style.RESET_ALL}")
def print_red(txt):     print(f"{Fore.RED}{txt}{Style.RESET_ALL}")
def print_yellow(txt):  print(f"{Fore.YELLOW}{txt}{Style.RESET_ALL}")
def print_magenta(txt): print(f"{Fore.MAGENTA}{txt}{Style.RESET_ALL}")

# --------------------------------------------------------------
# DNS IP Lookup
# --------------------------------------------------------------
async def get_ip(domain: str) -> Optional[str]:
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return answers[0].to_text()
    except:
        try:
            answers = dns.resolver.resolve(domain, 'AAAA')
            return answers[0].to_text()
        except:
            return None

# --------------------------------------------------------------
# Subdomain Discovery
# --------------------------------------------------------------
async def discover_subdomains(session: ClientSession, target: str, wordlist: List[str]) -> Dict[str, str]:
    found = {}
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    tasks = []

    async def check(prefix: str):
        async with semaphore:
            subdomain = f"{prefix}.{target}" if prefix else target
            url = f"http://{subdomain}"
            try:
                async with session.head(url, allow_redirects=True, timeout=10) as resp:
                    if resp.status < 400:
                        ip = await get_ip(subdomain)
                        found[subdomain] = ip or "N/A"
                        print_green(f"[+] SUBDOMAIN: {subdomain:<30} → {ip or 'No IP'}")
            except:
                pass
            await asyncio.sleep(REQUEST_DELAY)

    for word in wordlist:
        tasks.append(check(word))
    tasks.append(check(""))  # apex domain

    await asyncio.gather(*tasks)
    return found

# --------------------------------------------------------------
# Screenshot Helper
# --------------------------------------------------------------
async def take_screenshot(page, url: str, output_dir: Path):
    try:
        await page.goto(url, wait_until="networkidle", timeout=15000)
        filename = urlparse(url).netloc + "_" + urlparse(url).path.replace("/", "_").strip("_")[:50]
        if not filename.endswith(".png"):
            filename += ".png"
        filepath = output_dir / filename
        await page.screenshot(path=str(filepath), full_page=True)
        print_magenta(f"[📸] Screenshot: {filepath.name}")
    except Exception as e:
        print_red(f"[!] Screenshot failed {url}: {e}")

# --------------------------------------------------------------
# Crawler Class
# --------------------------------------------------------------
class Crawler:
    def __init__(self, start_urls: List[str], domain: str, screenshot: bool, output_dir: Path):
        self.start_urls = start_urls
        self.domain = domain.lower()
        self.visited: Set[str] = set()
        self.internal_links: Set[str] = set()
        self.external_links: Set[str] = set()
        self.screenshot = screenshot
        self.output_dir = output_dir
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        self.screenshot_dir = output_dir / "screenshots"
        if screenshot:
            self.screenshot_dir.mkdir(exist_ok=True)

    async def crawl(self):
        connector = TCPConnector(limit=MAX_CONCURRENT, ssl=False)
        headers = {"User-Agent": USER_AGENT}

        async with ClientSession(connector=connector, timeout=TIMEOUT, headers=headers) as session:
            robots = await self.fetch_robots(session)
            playwright = await async_playwright().start()
            browser = await playwright.chromium.launch(headless=True)
            context = await browser.new_context()

            tasks = [
                self.worker(session, url, robots, context)
                for url in self.start_urls
            ]
            await asyncio.gather(*tasks)

            await context.close()
            await browser.close()
            await playwright.stop()

        self.save_results()

    async def fetch_robots(self, session: ClientSession):
        url = f"https://{self.domain}/robots.txt"
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return None
                text = await resp.text()
                rerp = RobotExclusionRulesParser()
                rerp.parse(text)
                return rerp
        except:
            return None

    async def worker(self, session: ClientSession, url: str, robots, context):
        if url in self.visited:
            return
        self.visited.add(url)

        async with self.semaphore:
            if robots and not robots.is_allowed(USER_AGENT, url):
                print_yellow(f"[robots] Blocked: {url}")
                return

            try:
                async with session.get(url) as resp:
                    if "text/html" not in resp.headers.get("content-type", ""):
                        return
                    html = await resp.text()
            except Exception as e:
                print_red(f"[!] Fetch error {url}: {e}")
                return

            # Screenshot (first page of each domain)
            if self.screenshot and url.count("/") <= 3:
                page = await context.new_page()
                asyncio.create_task(take_screenshot(page, url, self.screenshot_dir))
                await page.close()

            await asyncio.sleep(REQUEST_DELAY)
            soup = BeautifulSoup(html, "html.parser")

            for link in soup.find_all("a", href=True):
                href = link["href"].strip()
                absolute = urljoin(url, href)
                parsed = urlparse(absolute)

                if parsed.scheme not in ("http", "https"):
                    continue

                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if parsed.query:
                    clean += f"?{parsed.query}"

                if parsed.netloc.lower().endswith(self.domain):
                    self.internal_links.add(clean)
                    if clean not in self.visited:
                        asyncio.create_task(self.worker(session, clean, robots, context))
                    print_green(f"[INT] {clean}")
                else:
                    self.external_links.add(clean)
                    print_cyan(f"[EXT] {clean}")

    def save_results(self):
        results = {
            "domain": self.domain,
            "pages_visited": len(self.visited),
            "internal_links": sorted(self.internal_links),
            "external_links": sorted(self.external_links),
        }
        json_path = self.output_dir / "results.json"
        json_path.write_text(json.dumps(results, indent=2))
        print_yellow(f"\n[+] Results saved to {json_path}")

# --------------------------------------------------------------
# Main
# --------------------------------------------------------------
async def main():
    parser = argparse.ArgumentParser(description="SubX: Subdomain Buster + Crawler + Screenshots")
    parser.add_argument("target", help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", type=Path, help="Custom wordlist file")
    parser.add_argument("--screenshots", action="store_true", help="Take screenshots of homepages")
    parser.add_argument("-o", "--output", type=Path, default=Path("subx_output"), help="Output directory")
    args = parser.parse_args()

    target = args.target.lower().strip().removeprefix("http://").removeprefix("https://").split("/")[0]
    args.output.mkdir(exist_ok=True)

    # Load wordlist
    wordlist = WORDLIST
    if args.wordlist and args.wordlist.is_file():
        wordlist = [line.strip() for line in args.wordlist.read_text().splitlines() if line.strip()]

    print_yellow(f"[*] Discovering subdomains for {target}...")
    async with aiohttp.ClientSession() as session:
        subdomains = await discover_subdomains(session, target, wordlist)

    if not subdomains:
        print_red("[!] No subdomains found. Exiting.")
        return

    # Build start URLs
    start_urls = set()
    for sub, ip in subdomains.items():
        start_urls.add(f"https://{sub}")
        start_urls.add(f"http://{sub}")

    print_yellow(f"[*] Crawling {len(start_urls)} entry points...")
    crawler = Crawler(
        start_urls=list(start_urls),
        domain=target,
        screenshot=args.screenshots,
        output_dir=args.output
    )
    await crawler.crawl()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print_red("\n[!] Stopped by user")
        sys.exit(0)