import argparse
import asyncio
import aiohttp
import time
import random
import json
import logging
import requests
from aiohttp import ClientSession
from asyncio import Semaphore
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Banner
banner = """
    github:holdmabeers<3

    ██████╗░██████╗░██╗██╗░░░██╗██╗██████╗░
    ██╔══██╗██╔══██╗██║██║░░░██║██║██╔══██╗
    ██████╔╝██████╔╝██║╚██╗░██╔╝██║██║░░██║
    ██╔═══╝░██╔══██╗██║░╚████╔╝░██║██║░░██║
    ██║░░░░░██║░░██║██║░░╚██╔╝░░██║██████╔╝
    ╚═╝░░░░░╚═╝░░╚═╝╚═╝░░░╚═╝░░░╚═╝╚═════╝
    By: Holdmabeers                     goodluck
    ig arrayzzz_    
"""

# Payloads untuk fuzzing dan pengujian
xss_payloads = [
    "<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>", 
    "<svg/onload=alert(1)>", "<iframe src='javascript:alert(1)'></iframe>", 
    "<body onload=alert(1)>", "<input type='text' value=''><script>alert(1)</script>",
    "<a href='javascript:alert(1)'>Click me</a>", "<img src=x onerror=alert(1)>",
    "<script>prompt(1)</script>", "<input autofocus onfocus='alert(1)'>"
]
sqli_payloads = [
    "' OR '1'='1", "' UNION SELECT null, null--", "1' OR 'a'='a", "admin' --",
    "' AND 1=1", "' OR 1=1#", "'; DROP TABLE users; --", "' OR 1=1#"
]
path_brute_force = [
    'admin', 'login', 'wp-admin', 'dashboard', 'config', 'user', 'test', 
    'api', 'docs', 'upload', 'uploads', 'secret', 'assets', 'secure', 'vulnerabilities'
]
dir_brute_force = [
    'uploads', 'files', 'data', 'bin', 'tmp', 'config', 'media', 'scripts', 'img'
]
file_brute_force = [
    'config.php', 'index.php', 'login.php', 'admin.php', 'db.php', 
    'config.json', 'web.config', 'settings.ini', 'backup.zip'
]

# Setup logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# Fungsi untuk mengecek status dan header HTTP
async def check_headers(url, session):
    try:
        async with session.head(url) as response:
            headers = response.headers
            if 'X-Powered-By' in headers:
                return f"[INFO] [Header] Found X-Powered-By: {headers['X-Powered-By']} at {url}"
            if 'Server' in headers:
                return f"[INFO] [Header] Server Header Detected: {headers['Server']} at {url}"
            if 'Access-Control-Allow-Origin' in headers:
                return f"[WARNING] [Header] Found CORS Misconfiguration at {url}"
            return f"[INFO] [Header] No notable headers found at {url}"
    except Exception as e:
        return f"[ERROR] [Header] Error with header check on {url}: {str(e)}"

# Fungsi untuk tes XSS
async def test_xss(url, session):
    for payload in xss_payloads:
        payload_url = url + payload
        try:
            async with session.get(payload_url) as response:
                if payload in await response.text():
                    return f"[WARNING] [XSS] Found XSS vulnerability at {url}"
        except Exception as e:
            return f"[ERROR] [XSS] Error with XSS test on {url}: {str(e)}"
    return f"[INFO] [XSS] No XSS vulnerabilities found at {url}"

# Fungsi untuk tes SQL Injection
async def test_sqli(url, session):
    for payload in sqli_payloads:
        payload_url = url + payload
        try:
            async with session.get(payload_url) as response:
                if "syntax error" in await response.text():
                    return f"[WARNING] [SQLi] Found SQL Injection vulnerability at {url}"
        except Exception as e:
            return f"[ERROR] [SQLi] Error with SQLi test on {url}: {str(e)}"
    return f"[INFO] [SQLi] No SQLi vulnerabilities found at {url}"

# Fungsi untuk mendeteksi open redirect
async def test_redirect(url, session):
    try:
        async with session.get(url, allow_redirects=False) as response:
            if response.status == 302 or response.status == 301:
                location = response.headers.get('Location')
                if location:
                    return f"[WARNING] [Redirect] Found Open Redirect at {url} -> {location}"
    except Exception as e:
        return f"[ERROR] [Redirect] Error with Redirect test on {url}: {str(e)}"
    return f"[INFO] [Redirect] No Open Redirect found at {url}"

# Fuzzing dan brute force untuk direktori atau file
async def brute_force(url, session, wordlist):
    for word in wordlist:
        full_url = urljoin(url, word)
        try:
            async with session.get(full_url) as response:
                if response.status == 200:
                    return f"[WARNING] [BruteForce] Found directory/file: {full_url}"
        except Exception as e:
            return f"[ERROR] [BruteForce] Error with brute force at {url}: {str(e)}"
    return f"[INFO] [BruteForce] No directories/files found at {url}"

# Fungsi untuk menguji otorisasi dan autentikasi
async def test_authentication(url, session):
    auth_payload = {"username": "admin", "password": "admin123"}
    try:
        async with session.post(url, data=auth_payload) as response:
            if response.status == 200:
                return f"[WARNING] [Auth] Found potential Authorization bypass: {url}"
    except Exception as e:
        return f"[ERROR] [Auth] Error with authorization test on {url}: {str(e)}"
    return f"[INFO] [Auth] No authorization bypass found at {url}"

# Fungsi untuk validasi SSL
async def validate_ssl(url, session):
    try:
        async with session.get(url, ssl=True) as response:
            if response.status != 200:
                return f"[ERROR] [SSL] SSL/TLS issues detected on {url}"
    except Exception as e:
        return f"[ERROR] [SSL] SSL Validation failed on {url}: {str(e)}"
    return f"[INFO] [SSL] SSL is valid at {url}"

# Fungsi untuk menguji setiap URL
async def fetch_url(url, session, semaphore, wordlist):
    async with semaphore:
        tasks = []
        tasks.append(test_authentication(url, session))
        tasks.append(test_xss(url, session))
        tasks.append(test_sqli(url, session))
        tasks.append(test_redirect(url, session))
        tasks.append(brute_force(url, session, wordlist))
        tasks.append(check_headers(url, session))
        tasks.append(validate_ssl(url, session))
        return await asyncio.gather(*tasks)

# Fungsi utama untuk mengambil URL dan menguji berbagai kerentanannya
async def main(urls, max_requests_per_second, wordlist):
    async with aiohttp.ClientSession() as session:
        semaphore = Semaphore(max_requests_per_second)
        tasks = []
        for url in urls:
            tasks.append(fetch_url(url, session, semaphore, wordlist))
        
        # Menunggu dan mencetak hasil tiap URL satu per satu
        for task in asyncio.as_completed(tasks):
            result = await task
            for res in result:
                logging.info(res)

# Membaca daftar URL dari file
def read_urls_from_file(file_path):
    with open(file_path, 'r') as f:
        urls = [line.strip() for line in f.readlines()]
    return urls

# Argument parser
def parse_arguments():
    parser = argparse.ArgumentParser(description="Advanced Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", help="URL tunggal untuk dipindai")
    parser.add_argument("-f", "--file", help="File dengan daftar URL untuk dipindai")
    parser.add_argument("-mps", "--max-requests-per-second", type=int, default=5, help="Jumlah maksimal permintaan per detik per thread")
    parser.add_argument("-w", "--wordlist", help="Path ke wordlist untuk fuzzing")
    parser.add_argument("-v", "--verbose", action="store_true", help="Aktifkan mode verbose")
    return parser.parse_args()

# Entry point
if __name__ == "__main__":
    print(banner)
    args = parse_arguments()

    urls_to_scan = []
    if args.url:
        urls_to_scan.append(args.url)
    elif args.file:
        urls_to_scan = read_urls_from_file(args.file)
    else:
        logging.info("[INFO] Tidak ada URL atau file yang diberikan")
        exit()

    # Menambahkan wordlist default jika tidak diberikan
    wordlist = path_brute_force if not args.wordlist else [line.strip() for line in open(args.wordlist)]

    # Menjalankan pemindaian
    asyncio.run(main(urls_to_scan, args.max_requests_per_second, wordlist))
