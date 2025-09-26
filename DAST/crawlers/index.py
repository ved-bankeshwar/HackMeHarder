import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl(base_url):
    """
    Crawls a website starting from the base_url to discover endpoints (links and forms).

    Args:
        base_url (str): The starting URL to crawl.

    Returns:
        list: A list of dictionaries, where each dictionary represents an attackable endpoint.
              Example: [{'url': '/login', 'method': 'POST', 'params': ['user', 'pass']}]
    """
    # Use a set to keep track of URLs to visit to avoid duplicate requests
    urls_to_visit = {base_url}  
    #print(type(urls_to_visit))
    # Use a set to store URLs that have already been visited
    visited_urls = set()
    # This will be our final output
    discovered_endpoints = []

    print(f"[*] Starting crawl at: {base_url}")

    # The main loop continues as long as there are new URLs to explore
    while urls_to_visit:
        current_url = urls_to_visit.pop()

        # Avoid re-visiting the same URL
        if current_url in visited_urls:
            continue

        print(f"  -> Crawling: {current_url}")
        visited_urls.add(current_url)

        try:
            # Make the HTTP GET request
            response = requests.get(current_url, timeout=5)
            response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

            # Use BeautifulSoup to parse the HTML content
            soup = BeautifulSoup(response.text, 'html.parser')

            # 1. Discover all links (<a> tags)
            for link in soup.find_all('a', href=True):
                href = link['href']
                # Use urljoin to handle relative paths (e.g., "/about.html")
                absolute_url = urljoin(current_url, href)

                # Parse the URL to ensure we stay on the same domain
                if urlparse(absolute_url).netloc == urlparse(base_url).netloc:
                    if absolute_url not in visited_urls:
                        urls_to_visit.add(absolute_url)

            # 2. Discover all forms (<form> tags)
            for form in soup.find_all('form'):
                action = form.get('action')
                # Resolve the form action URL, similar to links
                form_url = urljoin(current_url, action)
                method = form.get('method', 'GET').upper()
                
                params = []
                # Find all input, textarea, and select fields within the form
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    param_name = input_tag.get('name')
                    if param_name:
                        params.append(param_name)
                
                endpoint_info = {
                    'url': form_url,
                    'method': method,
                    'params': sorted(list(set(params))) # Store unique param names
                }
                
                # Add the form info if it's new
                if endpoint_info not in discovered_endpoints:
                    discovered_endpoints.append(endpoint_info)
                    print(f"    [+] Discovered Form: {method} to {form_url} with params {params}")


        except requests.RequestException as e:
            print(f"  [!] Error crawling {current_url}: {e}")
            continue

    print(f"[*] Crawl finished. Discovered {len(discovered_endpoints)} form endpoints.")
    return discovered_endpoints

# This block allows the script to be run directly for testing
if __name__ == "__main__":
    # A test site designed for this kind of scanning
    target_site = "http://testphp.vulnweb.com/"
    
    # Run the crawler
    endpoints = crawl(target_site)
    
    # Print the results in a clean format
    print("\n--- CRAWLER RESULTS ---")
    if endpoints:
        for endpoint in endpoints:
            print(f"URL: {endpoint['url']}, Method: {endpoint['method']}, Params: {endpoint['params']}")
    else:
        print("No form endpoints were discovered.")
    print("----------------------")
