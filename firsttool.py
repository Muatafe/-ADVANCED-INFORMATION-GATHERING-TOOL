import socket
import requests
import whois
import dns.resolver
import json
from urllib.parse import urlparse
import os
from datetime import datetime
from pystyle import *

print(Box.Lines("Created by MR-ROOT from Somalia"))

class InformationGatherer:
    def __init__(self):
        self.target = ""
        self.results = {}
        
    def display_banner(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        print("\033[91m" + "=" * 60)
        print(Box.Lines("Created by MR-ROOT from Somalia"))
        
        print("🔍 ADVANCED INFORMATION GATHERING TOOL")
        
        print("=" * 60 + "\033[0m")
    
    def main_menu(self):
        self.display_banner()
        print("\033[97m" + "=" * 60)
        print("\033[91m [1] Domain Information Gathering")
        print(" [2] IP Address Analysis") 
        print(" [3] Network Scanning")
        print(" [4] Website Technology Detection")
        print(" [5] Social Media Research")
        print(" [6] Generate Full Report")
        print(" [7] Exit")
        print("\033[97m" + "=" * 60 + "\033[0m")
    
    # 1. DOMAIN INFORMATION GATHERING
    def domain_info_gathering(self):
        print("\n\033[91m[+] Domain Information Gathering\033[0m")
        print("\033[97m" + "-" * 40 + "\033[0m")
        
        domain = input("Enter domain (example.com): ").strip()
        
        try:
            # WHOIS Lookup
            print("\n\033[93m[+] WHOIS Information:\033[0m")
            domain_info = whois.whois(domain)
            
            print(f"Domain: {domain_info.domain_name}")
            print(f"Registrar: {domain_info.registrar}")
            print(f"Creation Date: {domain_info.creation_date}")
            print(f"Expiration Date: {domain_info.expiration_date}")
            print(f"Name Servers: {', '.join(domain_info.name_servers) if domain_info.name_servers else 'N/A'}")
            
            # DNS Information
            print("\n\033[93m[+] DNS Records:\033[0m")
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    print(f"{record_type} Records:")
                    for rdata in answers:
                        print(f"  - {rdata}")
                except:
                    print(f"{record_type} Records: Not found")
                    
        except Exception as e:
            print(f"\033[91mError: {e}\033[0m")
    
    # 2. IP ADDRESS ANALYSIS
    def ip_analysis(self):
        print("\n\033[91m[+] IP Address Analysis\033[0m")
        print("\033[97m" + "-" * 40 + "\033[0m")
        
        ip = input("Enter IP address: ").strip()
        
        try:
            # IP Geolocation
            print("\n\033[93m[+] IP Geolocation:\033[0m")
            response = requests.get(f"http://ip-api.com/json/{ip}")
            geo_data = response.json()
            
            if geo_data['status'] == 'success':
                print(f"Country: {geo_data.get('country', 'N/A')}")
                print(f"Region: {geo_data.get('regionName', 'N/A')}")
                print(f"City: {geo_data.get('city', 'N/A')}")
                print(f"ISP: {geo_data.get('isp', 'N/A')}")
                print(f"Organization: {geo_data.get('org', 'N/A')}")
                print(f"Latitude: {geo_data.get('lat', 'N/A')}")
                print(f"Longitude: {geo_data.get('lon', 'N/A')}")
            else:
                print("Geolocation data not available")
                
            # Reverse DNS Lookup
            print("\n\033[93m[+] Reverse DNS:\033[0m")
            try:
                hostname = socket.gethostbyaddr(ip)
                print(f"Hostname: {hostname[0]}")
            except:
                print("Reverse DNS lookup failed")
                
        except Exception as e:
            print(f"\033[91mError: {e}\033[0m")
    
    # 3. NETWORK SCANNING
    def network_scanning(self):
        print("\n\033[91m[+] Network Port Scanning\033[0m")
        print("\033[97m" + "-" * 40 + "\033[0m")
        
        target = input("Enter target IP or domain: ").strip()
        
        try:
            # Resolve domain to IP if needed
            try:
                ip = socket.gethostbyname(target)
                print(f"Target IP: {ip}")
            except:
                ip = target
                
            print(f"\n\033[93mScanning common ports on {ip}...\033[0m")
            
            common_ports = {
                21: "FTP",
                22: "SSH",
                23: "Telnet",
                25: "SMTP",
                53: "DNS",
                80: "HTTP",
                110: "POP3",
                143: "IMAP",
                443: "HTTPS",
                993: "IMAPS",
                995: "POP3S",
                3389: "RDP"
            }
            
            open_ports = []
            
            for port, service in common_ports.items():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                
                result = sock.connect_ex((ip, port))
                if result == 0:
                    print(f"\033[92m[OPEN] Port {port} - {service}\033[0m")
                    open_ports.append((port, service))
                else:
                    print(f"\033[91m[CLOSED] Port {port} - {service}\033[0m")
                
                sock.close()
                
            print(f"\n\033[93mSummary: {len(open_ports)} ports open\033[0m")
            
        except Exception as e:
            print(f"\033[91mError: {e}\033[0m")
    
    # 4. WEBSITE TECHNOLOGY DETECTION
    def website_tech_detection(self):
        print("\n\033[91m[+] Website Technology Detection\033[0m")
        print("\033[97m" + "-" * 40 + "\033[0m")
        
        url = input("Enter website URL: ").strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        try:
            print(f"\n\033[93mAnalyzing {url}...\033[0m")
            
            response = requests.get(url, timeout=10)
            headers = response.headers
            
            # Server Information
            print("\n\033[93m[+] Server Information:\033[0m")
            print(f"Server: {headers.get('Server', 'Not detected')}")
            print(f"Powered By: {headers.get('X-Powered-By', 'Not detected')}")
            print(f"Content Type: {headers.get('Content-Type', 'Not detected')}")
            
            # Security Headers
            print("\n\033[93m[+] Security Headers:\033[0m")
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy', 
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection'
            ]
            
            for header in security_headers:
                if header in headers:
                    print(f"\033[92m{header}: {headers[header]}\033[0m")
                else:
                    print(f"\033[91m{header}: Missing\033[0m")
                    
            # Technologies (basic detection)
            print("\n\033[93m[+] Possible Technologies:\033[0m")
            content = response.text.lower()
            
            technologies = {
                'WordPress': 'wp-content' in content,
                'Joomla': 'joomla' in content or 'Joomla' in response.text,
                'Drupal': 'drupal' in content,
                'React': 'react' in content or '.js' in content,
                'jQuery': 'jquery' in content,
                'Bootstrap': 'bootstrap' in content,
                'Google Analytics': 'google-analytics' in content or 'ga(' in content,
                'Cloudflare': 'cloudflare' in headers.get('Server', ''),
                'Nginx': 'nginx' in headers.get('Server', ''),
                'Apache': 'apache' in headers.get('Server', '')
            }
            
            for tech, detected in technologies.items():
                if detected:
                    print(f"\033[92m✓ {tech}\033[0m")
                else:
                    print(f"\033[91m✗ {tech}\033[0m")
                    
        except Exception as e:
            print(f"\033[91mError: {e}\033[0m")
    
    # 5. SOCIAL MEDIA RESEARCH
    def social_media_research(self):
        print("\n\033[91m[+] Social Media Presence Check\033[0m")
        print("\033[97m" + "-" * 40 + "\033[0m")
        
        username = input("Enter username to search: ").strip()
        
        social_platforms = {
            'GitHub': f'https://github.com/{username}',
            'Twitter': f'https://twitter.com/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'Facebook': f'https://facebook.com/{username}',
            'LinkedIn': f'https://linkedin.com/in/{username}',
            'YouTube': f'https://youtube.com/@{username}'
            
        }
        
        print(f"\n\033[93mChecking social media for '{username}'...\033[0m")
        
        for platform, url in social_platforms.items():
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"\033[92m[FOUND] {platform}: {url}\033[0m")
                else:
                    print(f"\033[91m[NOT FOUND] {platform}\033[0m")
            except:
                print(f"\033[91m[ERROR] {platform}\033[0m")
    
    # 6. GENERATE REPORT
    def generate_report(self):
        print("\n\033[91m[+] Generating Comprehensive Report\033[0m")
        print("\033[97m" + "-" * 40 + "\033[0m")
        
        target = input("Enter target (domain/IP): ").strip()
        
        print(f"\n\033[93mGenerating report for {target}...\033[0m")
        
        # This would combine all the above functions
        # For simplicity, we'll just show a summary
        report_data = {
            'target': target,
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'domain_info': "Run domain scan for details",
            'ip_info': "Run IP analysis for details", 
            'network_scan': "Run network scan for details",
            'tech_info': "Run technology detection for details",
            'social_info': "Run social media research for details"
        }
        
        print("\n\033[93m[+] Report Summary:\033[0m")
        for key, value in report_data.items():
            print(f"{key.replace('_', ' ').title()}: {value}")
        
        # Save to file
        filename = f"scan_report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            for key, value in report_data.items():
                f.write(f"{key.replace('_', ' ').title()}: {value}\n")
        
        print(f"\n\033[92mReport saved to: {filename}\033[0m")
    
    def run(self):
        while True:
            self.main_menu()
            choice = input("\n\033[91mChoose option (1-7): \033[0m").strip()
            
            if choice == "1":
                self.domain_info_gathering()
            elif choice == "2":
                self.ip_analysis()
            elif choice == "3":
                self.network_scanning()
            elif choice == "4":
                self.website_tech_detection()
            elif choice == "5":
                self.social_media_research()
            elif choice == "6":
                self.generate_report()
            elif choice == "7":
                print("\n\033[92mThank you for using Information Gathering Tool! 👋\033[0m")
                break
            else:
                print("\n\033[91mInvalid choice! Please try again.\033[0m")
            
            input("\n\033[97mPress Enter to continue...\033[0m")

# Run the tool
if __name__ == "__main__":
    try:
        # Check required libraries
        import whois
        import dns.resolver
        
        tool = InformationGatherer()
        tool.run()
        
    except ImportError as e:
        print(f"\033[91mMissing required library: {e}\033[0m")
        print("\033[93mInstall required libraries with:\033[0m")
        print("pip install python-whois dnspython requests colorama")