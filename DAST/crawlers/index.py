import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl(base_url):
    
    
    urls_to_visit = {base_url}  

    visited_urls = set()
   
    discovered_endpoints = []

    print(f"[*] Starting crawl at: {base_url}")


    while urls_to_visit:
        current_url = urls_to_visit.pop()


        if current_url in visited_urls:
            continue

        print(f"  -> Crawling: {current_url}")
        visited_urls.add(current_url)

        try:
 
            response = requests.get(current_url, timeout=5)
            response.raise_for_status() 


            soup = BeautifulSoup(response.text, 'html.parser')

            for link in soup.find_all('a', href=True):
                href = link['href']

                absolute_url = urljoin(current_url, href)

                if urlparse(absolute_url).netloc == urlparse(base_url).netloc:
                    if absolute_url not in visited_urls:
                        urls_to_visit.add(absolute_url)

 
            for form in soup.find_all('form'):
                action = form.get('action')
  
                form_url = urljoin(current_url, action)
                method = form.get('method', 'GET').upper()
                
                params = []
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    param_name = input_tag.get('name')
                    if param_name:
                        params.append(param_name)
                
                endpoint_info = {
                    'url': form_url,
                    'method': method,
                    'params': sorted(list(set(params))) 
                }
                

                if endpoint_info not in discovered_endpoints:
                    discovered_endpoints.append(endpoint_info)
                    print(f"    [+] Discovered Form: {method} to {form_url} with params {params}")


        except requests.RequestException as e:
            print(f"  [!] Error crawling {current_url}: {e}")
            continue

    print(f"[*] Crawl finished. Discovered {len(discovered_endpoints)} form endpoints.")
    return discovered_endpoints


if __name__ == "__main__":
 
    target_site = "http://testphp.vulnweb.com/"
    

    endpoints = crawl(target_site)
    


    if endpoints:
        for endpoint in endpoints:
            print(f"URL: {endpoint['url']}, Method: {endpoint['method']}, Params: {endpoint['params']}")
    else:
        print("No form endpoints were discovered.")
    print("----------------------")
