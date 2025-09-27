# DAST/crawlers/index.py

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class Crawler:
    def __init__(self, base_url):
        self.base_url = base_url
        self.visited_urls = set()
        self.form_endpoints = []
        # Store all discovered links, not just forms
        self.discovered_links = set()

    def crawl(self, url=None):
        if url is None:
            url = self.base_url
        
        if url in self.visited_urls:
            return

        print(f"  -> Crawling: {url}")
        self.visited_urls.add(url)
        self.discovered_links.add(url) # Add the current URL to the list

        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"  [!] Error crawling {url}: {e}")
            return

        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all forms
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action')
            endpoint = urljoin(self.base_url, action)
            self.form_endpoints.append(endpoint)

        # --- FIX ---
        # Find all anchor (<a>) tags to discover linked pages
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            # Join the relative URL with the base URL
            absolute_url = urljoin(self.base_url, href)

            # Ensure we only crawl links within the same domain
            if urlparse(absolute_url).netloc == urlparse(self.base_url).netloc:
                # Recursively crawl the new link
                self.crawl(absolute_url)

    def run(self):
        print(f"[*] Starting crawl at: {self.base_url}")
        self.crawl()
        # Return all discovered links, not just forms
        print(f"[*] Crawl finished. Discovered {len(self.discovered_links)} unique links.")
        return list(self.discovered_links)