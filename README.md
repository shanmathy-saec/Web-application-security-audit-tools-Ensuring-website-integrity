# Web-application-security-audit-tools-Ensuring-website-integrity
import requests
import socket
import ssl

URL = "https://www.hackthebox.com/"  

def check_ssl_certificate(url):
    try:
        hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print("[+] SSL Certificate is valid for:", cert['subject'])
    except Exception as e:
        print("[-] SSL Certificate check failed:", str(e))

def check_http_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        security_headers = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security"]
        
        for header in security_headers:
            if header in headers:
                print(f"[+] {header} is present: {headers[header]}")
            else:
                print(f"[-] {header} is missing!")
    except Exception as e:
        print("[-] HTTP headers check failed:", str(e))

def check_sql_injection(url):
    test_payload = "' OR '1'='1"
    try:
        response = requests.get(url + test_payload)
        if "error" in response.text.lower() or "sql" in response.text.lower():
            print("[-] Possible SQL Injection vulnerability detected!")
        else:
            print("[+] No SQL Injection vulnerability detected.")
    except Exception as e:
        print("[-] SQL Injection test failed:", str(e))

def check_xss(url):
    test_payload = "<script>alert('XSS')</script>"
    try:
        response = requests.get(url + test_payload)
        if test_payload in response.text:
            print("[-] Possible XSS vulnerability detected!")
        else:
            print("[+] No XSS vulnerability detected.")
    except Exception as e:
        print("[-] XSS test failed:", str(e))

if __name__ == "__main__":
    print(f"Starting Security Audit for: {URL}")
    check_ssl_certificate(URL)
    check_http_headers(URL)
    check_sql_injection(URL)
    check_xss(URL)
    print("Security Audit Completed.")
