# scanner.py - Core scanning engine for DorkStrike PRO

import asyncio
import aiohttp
import aiodns
import requests
import re
import time
import threading
import random
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from bs4 import BeautifulSoup
from patterns import DorkPatterns, validate_crypto_pattern, validate_secret_pattern, calculate_shannon_entropy, verify_api_key
from fake_useragent import UserAgent

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

class DorkScanner:
    def __init__(self, proxies=None, search_engines=None, use_js_rendering=False, verify_api_keys=False, strictness="medium", depth=3, custom_dorks=None):
        self.patterns = DorkPatterns()
        self.stop_event = threading.Event()
        self.session = requests.Session()
        self.proxies = proxies or []
        self.ua = UserAgent()
        self.search_engines = search_engines or ['google']  # Default to Google
        self.use_js_rendering = use_js_rendering and PLAYWRIGHT_AVAILABLE
        self.verify_api_keys = verify_api_keys
        self.dns_resolver = None
        self.strictness = strictness.lower()
        self.depth = depth
        self.request_count = 0
        self.custom_dorks = custom_dorks or []

    def stop_scan(self):
        self.stop_event.set()

    async def scan_async(self, target_domain, pattern_category, max_concurrent, progress_callback, log_callback, finding_callback):
        """Async version of scan method"""
        start_time = time.time()

        # Generate dork URLs
        dork_urls = self.generate_dork_urls(target_domain, pattern_category)
        total_urls = len(dork_urls)

        log_callback(f"Generated {total_urls} dork URLs for scanning")

        results = {
            'total_urls': total_urls,
            'findings_count': 0,
            'pattern_breakdown': {},
            'duration': 0,
            'avg_response_time': 0
        }

        findings = []
        response_times = []

        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(max_concurrent)

        # Create aiohttp session with connector settings
        connector = aiohttp.TCPConnector(limit=max_concurrent, ttl_dns_cache=300)
        timeout = aiohttp.ClientTimeout(total=10, connect=5)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = []
            completed = 0

            for url_data in dork_urls:
                if self.stop_event.is_set():
                    break

                task = asyncio.create_task(self.scan_url_async(session, url_data, pattern_category, semaphore))
                tasks.append(task)

                # Process completed tasks in batches to update progress
                if len(tasks) >= max_concurrent:
                    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    tasks = list(pending)

                    for task in done:
                        try:
                            url_findings, response_time = task.result()
                            response_times.append(response_time)
                            findings.extend(url_findings)

                            for finding in url_findings:
                                finding_callback(finding['type'], finding['pattern'], finding['url'], finding['match'], finding.get('verification', 'Format valid'))
                                results['findings_count'] += 1

                                pattern_type = finding['type']
                                if pattern_type not in results['pattern_breakdown']:
                                    results['pattern_breakdown'][pattern_type] = 0
                                results['pattern_breakdown'][pattern_type] += 1

                        except Exception as e:
                            log_callback(f"Error processing task: {str(e)}")

                        completed += 1
                        progress = (completed / total_urls) * 100
                        progress_callback(progress)

            # Process remaining tasks
            if tasks:
                done, _ = await asyncio.wait(tasks)
                for task in done:
                    try:
                        url_findings, response_time = task.result()
                        response_times.append(response_time)
                        findings.extend(url_findings)

                        for finding in url_findings:
                            finding_callback(finding['type'], finding['pattern'], finding['url'], finding['match'], finding.get('verification', 'Format valid'))
                            results['findings_count'] += 1

                            pattern_type = finding['type']
                            if pattern_type not in results['pattern_breakdown']:
                                results['pattern_breakdown'][pattern_type] = 0
                            results['pattern_breakdown'][pattern_type] += 1

                    except Exception as e:
                        log_callback(f"Error processing final task: {str(e)}")

                    completed += 1
                    progress = (completed / total_urls) * 100
                    progress_callback(progress)

        results['duration'] = time.time() - start_time
        if response_times:
            results['avg_response_time'] = sum(response_times) / len(response_times)

        log_callback(f"Scan completed. Found {results['findings_count']} potential vulnerabilities.")
        return results

    def scan(self, target_domain, pattern_category, max_concurrent, progress_callback, log_callback, finding_callback):
        """Main scan method - now uses asyncio internally"""
        self.stop_event.clear()

        # Create a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            # Run the async scan
            results = loop.run_until_complete(
                self.scan_async(target_domain, pattern_category, max_concurrent, progress_callback, log_callback, finding_callback)
            )
            return results
        finally:
            loop.close()

    def generate_dork_urls(self, target_domain, pattern_category):
        """Generate dork URLs for multiple search engines"""
        base_urls = [
            f"site:{target_domain}",
            f"site:{target_domain} inurl:",
            f"site:{target_domain} filetype:",
            f"site:{target_domain} intitle:",
        ]

        dork_urls = []

        if pattern_category == "ALL":
            categories = ["CRYPTO", "SECRETS", "VULNERABILITIES"]
        else:
            categories = [pattern_category]

        # Add custom dorks first
        if self.custom_dorks:
            for engine in self.search_engines:
                for custom_dork in self.custom_dorks:
                    # Replace {target} placeholder with actual domain
                    dork = custom_dork.replace("{target}", target_domain)
                    search_url = self._generate_search_url(engine, dork)
                    if search_url:
                        dork_urls.append((search_url, "Custom Dork", "CUSTOM"))

        # Add pattern-based dorks
        for engine in self.search_engines:
            for category in categories:
                patterns = self.patterns.get_patterns(category)
                for pattern_name, pattern_data in patterns.items():
                    dorks = pattern_data.get('dorks', [])
                    for dork in dorks:
                        for base_url in base_urls:
                            full_dork = f"{base_url} {dork}"
                            # Generate URL for each search engine
                            search_url = self._generate_search_url(engine, full_dork)
                            if search_url:
                                dork_urls.append((search_url, pattern_name, category))

        return dork_urls

    def _generate_search_url(self, engine, query):
        """Generate search URL for different engines"""
        query_encoded = query.replace(' ', '+')

        if engine == 'google':
            return f"https://www.google.com/search?q={query_encoded}&num=100"
        elif engine == 'duckduckgo':
            return f"https://duckduckgo.com/?q={query_encoded}&ia=web"
        elif engine == 'bing':
            return f"https://www.bing.com/search?q={query_encoded}&count=50"
        elif engine == 'shodan':
            # Shodan uses different syntax
            return f"https://www.shodan.io/search?query={query_encoded}"
        elif engine == 'wayback':
            # Wayback Machine CDX API
            return f"https://web.archive.org/cdx/search/cdx?url={query_encoded}&output=json"
        return None

    async def check_dns_resolution(self, domain):
        """Check if domain resolves to IP addresses"""
        try:
            if not self.dns_resolver:
                self.dns_resolver = aiodns.DNSResolver()
            result = await self.dns_resolver.query(domain, 'A')
            return len(result) > 0
        except:
            return False

    def get_fresh_user_agent(self):
        """Get a fresh user agent, rotating frequently"""
        self.request_count += 1
        try:
            return self.ua.random
        except:
            # Fallback user agents
            fallback_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'
            ]
            return fallback_agents[self.request_count % len(fallback_agents)]

    def render_page_with_js(self, url):
        """Render page with JavaScript using Playwright"""
        if not self.use_js_rendering or not PLAYWRIGHT_AVAILABLE:
            return None

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    user_agent=self.ua.random,
                    viewport={'width': 1920, 'height': 1080}
                )
                page = context.new_page()

                # Set timeout and navigate
                page.goto(url, wait_until="networkidle", timeout=30000)

                # Wait a bit for dynamic content
                page.wait_for_timeout(2000)

                # Get the rendered HTML
                html_content = page.content()

                browser.close()
                return html_content
        except Exception as e:
            print(f"JS rendering failed for {url}: {e}")
            return None

    async def scan_url_async(self, session, url_data, pattern_category, semaphore):
        """Async version of scan_url with DNS check"""
        url, pattern_name, category = url_data
        start_time = time.time()

        async with semaphore:  # Limit concurrent requests
            try:
                # Extract domain for DNS check
                parsed = urlparse(url)
                domain = parsed.netloc

                # Check DNS resolution first
                if not await self.check_dns_resolution(domain):
                    return [], time.time() - start_time

                # Use JS rendering if enabled
                html_content = None
                if self.use_js_rendering:
                    # Run JS rendering in thread pool since Playwright is sync
                    loop = asyncio.get_event_loop()
                    html_content = await loop.run_in_executor(None, self.render_page_with_js, url)
                else:
                    # Use aiohttp for regular requests
                    headers = {'User-Agent': self.get_fresh_user_agent()}
                    timeout = aiohttp.ClientTimeout(total=10)

                    async with session.get(url, headers=headers, timeout=timeout) as response:
                        if response.status == 200:
                            html_content = await response.text()
                        else:
                            return [], time.time() - start_time

                if html_content:
                    # Run analysis in thread pool since it's CPU-bound
                    loop = asyncio.get_event_loop()
                    findings = await loop.run_in_executor(None, self.analyze_response, html_content, url, pattern_name, category)
                    return findings, time.time() - start_time
                else:
                    return [], time.time() - start_time

            except Exception:
                return [], time.time() - start_time

    def scan_url(self, url_data, pattern_category):
        """Scan a single dork URL with optional JS rendering"""
        url, pattern_name, category = url_data
        start_time = time.time()

        try:
            html_content = None

            # Try JS rendering first if enabled
            if self.use_js_rendering:
                html_content = self.render_page_with_js(url)
                response_time = time.time() - start_time
            else:
                # Fallback to regular requests
                if self.proxies:
                    proxy = random.choice(self.proxies)
                    self.session.proxies = {'http': proxy, 'https': proxy}
                self.session.headers['User-Agent'] = self.ua.random
                time.sleep(random.uniform(self.delay, self.delay + 8))
                response = self.session.get(url, timeout=10)
                response_time = time.time() - start_time

                if response.status_code == 200:
                    html_content = response.text
                else:
                    return [], response_time

            if html_content:
                findings = self.analyze_response(html_content, url, pattern_name, category)
                return findings, response_time
            else:
                return [], response_time

        except Exception:
            return [], time.time() - start_time

    def analyze_response(self, html_content, url, pattern_name, category):
        """Analyze the HTML content for patterns with validation"""
        findings = []

        patterns = self.patterns.get_patterns(category)
        if pattern_name in patterns:
            pattern_data = patterns[pattern_name]
            regex_patterns = pattern_data.get('regex', [])

            for regex in regex_patterns:
                try:
                    matches = re.findall(regex, html_content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        match_str = str(match)[:100]  # Limit match length

                        # Apply validation based on category
                        is_valid = True
                        verification_status = "Format valid"

                        if category == "CRYPTO":
                            is_valid = validate_crypto_pattern(pattern_name, match_str)
                            if not is_valid:
                                verification_status = "Invalid checksum"
                        elif category == "SECRETS":
                            is_valid = validate_secret_pattern(pattern_name, match_str)
                            if not is_valid:
                                verification_status = "Low entropy or invalid format"

                            # Additional API verification for supported services
                            if is_valid and self.verify_api_keys and category == "SECRETS":
                                # Run async verification in current thread
                                try:
                                    loop = asyncio.new_event_loop()
                                    asyncio.set_event_loop(loop)
                                    verified, status = loop.run_until_complete(
                                        verify_api_key(pattern_name, match_str)
                                    )
                                    loop.close()

                                    if verified:
                                        verification_status = f"Live verified: {status}"
                                    else:
                                        verification_status = f"Live check failed: {status}"
                                        is_valid = False  # Mark as invalid if live check fails
                                except Exception as e:
                                    verification_status = f"Verification error: {str(e)}"

                        if is_valid:
                            findings.append({
                                'type': category,
                                'pattern': pattern_name,
                                'url': url,
                                'match': match_str,
                                'verification': verification_status
                            })
                except re.error:
                    continue  # Skip invalid regex patterns

        return findings

    def local_scan(self, file_paths, pattern_category, log_callback, finding_callback):

        results = {

            'total_urls': len(file_paths),

            'findings_count': 0,

            'pattern_breakdown': {},

            'duration': 0,

            'avg_response_time': 0

        }

        start_time = time.time()

        for file_path in file_paths:

            file_path = file_path.strip()

            if not file_path:

                continue

            try:

                with open(file_path, 'r', encoding='utf-8') as f:

                    content = f.read()

                findings = self.analyze_response(content, file_path, "Local File", pattern_category)

                for finding in findings:

                    finding_callback(finding['type'], finding['pattern'], finding['url'], finding['match'], finding.get('verification', 'Format valid'))

                    results['findings_count'] += 1

                    pattern_type = finding['type']

                    if pattern_type not in results['pattern_breakdown']:

                        results['pattern_breakdown'][pattern_type] = 0

                    results['pattern_breakdown'][pattern_type] += 1

            except Exception as e:

                log_callback(f"Error scanning file {file_path}: {str(e)}")

        results['duration'] = time.time() - start_time

        return results

    def crawl_domain(self, domain, max_pages=100):
        """Crawl the domain to find additional URLs for scanning"""
        visited = set()
        to_visit = [f"https://{domain}", f"http://{domain}"]
        found_urls = []

        while to_visit and len(found_urls) < max_pages and not self.stop_event.is_set():
            current_url = to_visit.pop(0)
            if current_url in visited:
                continue

            visited.add(current_url)

            try:
                if self.proxies:
                    proxy = random.choice(self.proxies)
                    self.session.proxies = {'http': proxy, 'https': proxy}
                self.session.headers['User-Agent'] = self.ua.random
                time.sleep(random.uniform(self.delay, self.delay + 8))
                response = self.session.get(current_url, timeout=5)
                if response.status_code == 200:
                    found_urls.append(current_url)

                    # Extract links from the page
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        absolute_url = urljoin(current_url, href)
                        parsed = urlparse(absolute_url)

                        if parsed.netloc == domain and absolute_url not in visited:
                            to_visit.append(absolute_url)

            except:
                continue

        return found_urls