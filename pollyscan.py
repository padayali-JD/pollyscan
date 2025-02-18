import requests
import re
from urllib.parse import urlparse

def banner():
    font = """

  _____      _ _                           
 |  __ \    | | |                          
 | |__) |__ | | |_   _ ___  ___ __ _ _ __  
 |  ___/ _ \| | | | | / __|/ __/ _` | '_ \ 
 | |  | (_) | | | |_| \__ \ (_| (_| | | | |
 |_|   \___/|_|_|\__, |___/\___\__,_|_| |_|
                  __/ |                    
                 |___/                     Tool by Joby Daniel(Padayali-JD) """
    print(font)

if __name__ == "__main__":
    banner()

def check_cve_2024_38526(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error fetching URL: {e}")
        return False
    
    # Check for references to polyfill.io and known malicious domains
    vulnerable_domains = [
        "polyfill.io",
        "cdn.polyfill.io",
        "cdn.polyfill.dev",
        "polyfill.dev"
    ]
    
    matches = re.findall(r'src=["\'](https?://[^"\']+)["\']', response.text)
    vulnerable_urls = [link for link in matches if any(domain in link for domain in vulnerable_domains)]
    
    if vulnerable_urls:
        print("Potential vulnerability detected! The following scripts may be compromised:")
        for v_url in vulnerable_urls:
            print(f"- {v_url}")
        return True
    else:
        print("No known vulnerable scripts found.")
        return False

if __name__ == "__main__":
    target_url = input("Enter the URL to check: ")
    check_cve_2024_38526(target_url)
