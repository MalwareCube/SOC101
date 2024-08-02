import re
import sys
import quopri
import hashlib
import ipaddress
import requests
import email

def read_file(file_path):
    with open(file_path, 'rb') as file:
        content = file.read()
    parser = email.parser.BytesParser()
    msg = parser.parsebytes(content)
    return msg

def extract_ips(email_message):
    ips = set()
    
    # Extract IP addresses from headers
    for header_name, header_value in email_message.items():
        ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header_value))
    
    # Extract IP addresses from email body
    for part in email_message.walk():
        content_type = part.get_content_type()
        if content_type == 'text/plain' or content_type == 'text/html':
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8', errors='ignore')
            ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', payload))
    
    valid_ips = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
            valid_ips.append(ip)
        except ValueError:
            pass
    return list(set(valid_ips))

def extract_urls(email_message):
    urls = set()
    for part in email_message.walk():
        content_type = part.get_content_type()
        if content_type == 'text/plain' or content_type == 'text/html':
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8', errors='ignore')
            urls.update(re.findall(r'https?:\/\/(?:[\w\-]+\.)+[a-z]{2,}(?:\/[\w\-\.\/?%&=]*)?', payload))
    return list(urls)

def defang_ip(ip):
    return ip.replace('.', '[.]')

def defang_url(url):
    url = url.replace('https://', 'hxxps[://]')
    url = url.replace('.', '[.]')
    return url

def is_reserved_ip(ip):
    private_ranges = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
    ]
    reserved_ranges = [
        '0.0.0.0/8',
        '100.64.0.0/10',
        '169.254.0.0/16',
        '192.0.0.0/24',
        '192.0.2.0/24',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '224.0.0.0/4', 
        '240.0.0.0/4',
    ]
    for r in private_ranges + reserved_ranges:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(r):
            return True
    return False

def ip_lookup(ip):
    if is_reserved_ip(ip):
        return None
    
    url = f"https://ipinfo.io/{ip}/json"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return {
            'IP': data.get('ip', ''),
            'City': data.get('city', ''),
            'Region': data.get('region', ''),
            'Country': data.get('country', ''),
            'Location': data.get('loc', ''),
            'ISP': data.get('org', ''),
            'Postal Code': data.get('postal', '')
        }
    else:
        return None

def extract_headers(email_message):
    headers_to_extract = [
        "Date",
        "Subject",
        "To",
        "From",
        "Reply-To",
        "Return-Path",
        "Message-ID",
        "X-Originating-IP",
        "X-Sender-IP",
        "Authentication-Results"
    ]
    headers = {}
    for key in email_message.keys():
        if key in headers_to_extract:
            headers[key] = email_message[key]
    return headers

def extract_attachments(email_message):
    attachments = []
    for part in email_message.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None:
            continue
        filename = part.get_filename()
        if filename:
            attachments.append({
                'filename': filename,
                'md5': hashlib.md5(part.get_payload(decode=True)).hexdigest(),
                'sha1': hashlib.sha1(part.get_payload(decode=True)).hexdigest(),
                'sha256': hashlib.sha256(part.get_payload(decode=True)).hexdigest()
            })
    return attachments

def main(file_path):
    email_message = read_file(file_path)
    ips = extract_ips(email_message)
    urls = extract_urls(email_message)
    headers = extract_headers(email_message)
    attachments = extract_attachments(email_message)

    print("Extracted IP Addresses:")
    print("====================================")
    for ip in ips:
        defanged_ip = defang_ip(ip)
        ip_info = ip_lookup(ip)
        if ip_info:
            print(f"{defanged_ip} - {ip_info['City']}, {ip_info['Region']}, {ip_info['Country']}, ISP: {ip_info['ISP']}")
        else:
            print(defanged_ip)

    print("\nExtracted URLs:")
    print("====================================")
    for url in urls:
        print(defang_url(url))

    print("\nExtracted Headers:")
    print("====================================")
    for key, value in headers.items():
        print(f"{key}: {value}")

    print("\nExtracted Attachments:")
    print("====================================")
    for attachment in attachments:
        print(f"Filename: {attachment['filename']}")
        print(f"MD5: {attachment['md5']}")
        print(f"SHA1: {attachment['sha1']}")
        print(f"SHA256: {attachment['sha256']}")
        print()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    main(file_path)
