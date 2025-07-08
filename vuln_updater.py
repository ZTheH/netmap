#!/usr/bin/env python3
"""
Vulnerability Database Updater - DEPRECATED

⚠️  DEPRECATION NOTICE ⚠️
This standalone updater has been DEPRECATED and integrated into the main scanner.
The background update functionality is now built into script.py for seamless operation.

The main scanner (script.py) now includes:
- Automatic background CVE database updates (15 seconds after startup)
- Smart file age checking (updates only if database is >7 days old)
- Zero startup delay - uses built-in database immediately
- Minimal API calls to prevent rate limiting
- Comprehensive built-in database with 500+ CVEs

For manual updates, you can still run this script, but it's no longer necessary.
The scanner will automatically keep your CVE database current in the background.

Legacy functionality preserved below for compatibility.
"""

import requests
import json
import time
import os
from typing import Dict, List

# Show deprecation warning
print("⚠️  DEPRECATION NOTICE")
print("=" * 50)
print("This standalone updater has been DEPRECATED.")
print("CVE updates are now integrated into the main scanner (script.py).")
print("The scanner automatically updates the database in the background.")
print("=" * 50)
print()

class VulnerabilityUpdater:
    def __init__(self):
        self.sources = {
            'circl': 'https://vulnerability.circl.lu/api',
            'cve_circl': 'https://cve.circl.lu/api'
        }
        
    def fetch_circl_data(self, vendor: str, product: str = None) -> List[Dict]:
        """Fetch vulnerability data from CIRCL API"""
        try:
            if product:
                url = f"{self.sources['cve_circl']}/search/{vendor}/{product}"
            else:
                url = f"{self.sources['cve_circl']}/browse/{vendor}"
            
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"Error fetching CIRCL data for {vendor}/{product}: {e}")
        return []
    
    def fetch_recent_cves(self) -> List[Dict]:
        """Fetch recent CVEs from CIRCL"""
        try:
            url = f"{self.sources['cve_circl']}/last"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"Error fetching recent CVEs: {e}")
        return []
    
    def create_enhanced_database(self):
        """Create enhanced vulnerability database"""
        enhanced_db = {}
        
        # Software mappings for CVE lookup
        software_mappings = {
            'Apache': [('apache', 'http_server'), ('apache', 'tomcat')],
            'nginx': [('nginx', 'nginx')],
            'OpenSSH': [('openbsd', 'openssh')],
            'MySQL': [('mysql', 'mysql'), ('oracle', 'mysql')],
            'PostgreSQL': [('postgresql', 'postgresql')],
            'Microsoft-IIS': [('microsoft', 'internet_information_server')],
            'Telnet': [('telnet', None)],
            'FTP': [('vsftpd', None), ('proftpd', None)],
            'SMB': [('microsoft', 'windows'), ('samba', 'samba')],
            'RDP': [('microsoft', 'terminal_services')]
        }
        
        print("🔍 Fetching vulnerability data from CIRCL API...")
        
        for service, mappings in software_mappings.items():
            print(f"  📡 Fetching data for {service}...")
            enhanced_db[service] = []
            
            for vendor, product in mappings:
                try:
                    vulns = self.fetch_circl_data(vendor, product)
                    if isinstance(vulns, list):
                        for vuln in vulns[:5]:  # Limit to prevent overwhelming
                            if isinstance(vuln, dict) and 'id' in vuln:
                                cve_id = vuln['id']
                                summary = vuln.get('summary', 'No description available')[:100]
                                if len(summary) == 100:
                                    summary += "..."
                                enhanced_db[service].append(f"{cve_id} ({summary})")
                except Exception as e:
                    print(f"    ⚠️ Error processing {vendor}/{product}: {e}")
                
                time.sleep(0.5)  # Rate limiting
        
        # Add recent high-severity CVEs
        print("  📡 Fetching recent critical CVEs...")
        try:
            recent_cves = self.fetch_recent_cves()
            if isinstance(recent_cves, list):
                enhanced_db['Recent_Critical'] = []
                for cve in recent_cves[:10]:
                    if isinstance(cve, dict) and 'id' in cve:
                        cve_id = cve['id']
                        summary = cve.get('summary', 'Recent vulnerability')[:80]
                        if len(summary) == 80:
                            summary += "..."
                        enhanced_db['Recent_Critical'].append(f"{cve_id} ({summary})")
        except Exception as e:
            print(f"    ⚠️ Error fetching recent CVEs: {e}")
        
        return enhanced_db
    
    def get_builtin_enhanced_database(self):
        """Get comprehensive built-in vulnerability database"""
        return {
            "Apache/2.2": [
                "CVE-2009-3555 (SSL/TLS Renegotiation DoS - Critical)",
                "CVE-2010-0408 (mod_proxy_ajp denial of service)",
                "CVE-2010-0434 (mod_headers buffer overflow)",
                "CVE-2011-3192 (Range header DoS - Apache Killer)",
                "CVE-2011-3348 (mod_proxy_ajp remote DoS)",
                "CVE-2012-0021 (mod_log_config crash)",
                "CVE-2012-0053 (HTTP response splitting)"
            ],
            "Apache/2.4": [
                "CVE-2021-44228 (Log4Shell - Critical RCE if using vulnerable log4j)",
                "CVE-2021-42013 (Path traversal and remote code execution)",
                "CVE-2021-41773 (Path traversal vulnerability)",
                "CVE-2021-40438 (mod_proxy SSRF vulnerability)",
                "CVE-2022-22720 (HTTP request smuggling)",
                "CVE-2022-22719 (mod_lua use-after-free)",
                "CVE-2023-25690 (HTTP request smuggling)",
                "CVE-2023-27522 (mod_proxy_uwsgi HTTP response splitting)"
            ],
            "nginx": [
                "CVE-2019-20372 (HTTP request smuggling)",
                "CVE-2021-23017 (Resolver off-by-one heap write)",
                "CVE-2022-41741 (HTTP/2 implementation memory disclosure)",
                "CVE-2022-41742 (HTTP/2 implementation memory disclosure)",
                "CVE-2013-2028 (Stack buffer overflow in nginx)",
                "CVE-2016-0742 (Invalid pointer dereference)",
                "CVE-2016-0746 (Use-after-free vulnerability)",
                "CVE-2016-0747 (Resolver buffer overflow)"
            ],
            "OpenSSH": [
                "CVE-2020-14145 (Observable discrepancy)",
                "CVE-2021-41617 (Privilege escalation)",
                "CVE-2023-38408 (Remote code execution in ssh-agent)",
                "CVE-2023-51385 (Command injection via hostname)",
                "CVE-2016-0777 (Information disclosure)",
                "CVE-2016-0778 (Buffer overflow)",
                "CVE-2018-15473 (Username enumeration)",
                "CVE-2018-20685 (scp client vulnerability)"
            ],
            "OpenSSH_5.3": [
                "CVE-2010-4478 (OpenSSH Xauth/Kerberos vulnerability)",
                "CVE-2010-5107 (GSSAPI key exchange vulnerability)",
                "CVE-2011-4327 (Privilege escalation)",
                "CVE-2012-0814 (Memory corruption)"
            ],
            "OpenSSH_7.4": [
                "CVE-2016-10009 (Privilege escalation via malicious .ssh/config)",
                "CVE-2016-10010 (Privilege escalation via crafted X11 forwarding)",
                "CVE-2016-10011 (Information disclosure)",
                "CVE-2016-10012 (Information disclosure in shared memory)"
            ],
            "vsFTPd": [
                "CVE-2011-2523 (Backdoor Command Execution - Critical!)",
                "CVE-2015-1419 (Denial of service)",
                "CVE-2021-3618 (Memory disclosure)"
            ],
            "Microsoft-IIS": [
                "CVE-2017-7269 (Buffer overflow in WebDAV service - Critical)",
                "CVE-2021-31166 (HTTP protocol stack remote code execution)",
                "CVE-2022-21907 (HTTP protocol stack vulnerability)",
                "CVE-2015-1635 (HTTP.sys remote code execution)",
                "CVE-2015-1637 (HTTP.sys denial of service)",
                "CVE-2021-26855 (Exchange Server SSRF - ProxyLogon)",
                "CVE-2021-27065 (Exchange Server RCE - ProxyLogon)"
            ],
            "MySQL": [
                "CVE-2021-2154 (Server DML vulnerability)",
                "CVE-2021-2166 (Server DML vulnerability)",
                "CVE-2023-21980 (Server Optimizer vulnerability)",
                "CVE-2023-21912 (Server Partition vulnerability)",
                "CVE-2022-21245 (Server Security Privileges vulnerability)",
                "CVE-2021-35604 (Server InnoDB vulnerability)",
                "CVE-2021-2022 (Server DDL vulnerability)",
                "CVE-2020-14765 (Server FTS vulnerability)"
            ],
            "PostgreSQL": [
                "CVE-2021-32027 (Memory disclosure vulnerability)",
                "CVE-2021-32028 (Memory disclosure vulnerability)",
                "CVE-2023-39417 (Extension script execution)",
                "CVE-2023-39418 (MERGE privilege escalation)",
                "CVE-2022-1552 (Autovacuum privilege escalation)",
                "CVE-2021-23214 (libpq man-in-the-middle)",
                "CVE-2021-23222 (libpq man-in-the-middle)",
                "CVE-2020-25695 (Multiple buffer overflows)"
            ],
            "Telnet": [
                "CVE-2020-10188 (Telnet vulnerability)",
                "CVE-2011-4862 (Telnet daemon buffer overflow)",
                "Unencrypted protocol - credentials sent in plain text",
                "MITM attacks possible - no encryption",
                "Session hijacking vulnerability",
                "Eavesdropping on all communications"
            ],
            "FTP": [
                "CVE-2020-15778 (OpenSSH scp vulnerability)",
                "CVE-2019-6111 (scp client vulnerability)",
                "Unencrypted protocol - credentials and data sent in plain text",
                "MITM attacks possible - no encryption",
                "Anonymous FTP may expose sensitive data",
                "Brute force attacks on credentials"
            ],
            "SMB": [
                "CVE-2017-0144 (EternalBlue - SMBv1 Remote Code Execution - Critical)",
                "CVE-2017-0145 (EternalBlue - SMBv1 Remote Code Execution)",
                "CVE-2017-0146 (EternalBlue - SMBv1 Remote Code Execution)",
                "CVE-2017-0147 (EternalBlue - SMBv1 Information Disclosure)",
                "CVE-2017-0148 (EternalBlue - SMBv1 Remote Code Execution)",
                "CVE-2020-0796 (SMBGhost - SMBv3 Remote Code Execution)",
                "CVE-2021-31956 (Windows NTFS Privilege Escalation)",
                "CVE-2022-37969 (Windows Common Log File System Driver)"
            ],
            "RDP": [
                "CVE-2019-0708 (BlueKeep - Remote Code Execution - Critical)",
                "CVE-2020-0609 (Remote Desktop Gateway RCE)",
                "CVE-2020-0610 (Remote Desktop Gateway RCE)",
                "CVE-2019-1181 (Remote Desktop Services RCE)",
                "CVE-2019-1182 (Remote Desktop Services RCE)",
                "CVE-2019-1222 (Remote Desktop Services RCE)",
                "CVE-2019-1226 (Remote Desktop Services RCE)",
                "CVE-2022-30190 (Follina - MSDT RCE)"
            ],
            "HTTP": [
                "CVE-2021-44228 (Log4Shell - if using vulnerable log4j)",
                "CVE-2021-45046 (Log4Shell bypass)",
                "CVE-2022-22965 (Spring4Shell - Spring Framework RCE)",
                "CVE-2017-5638 (Apache Struts2 RCE)",
                "CVE-2018-11776 (Apache Struts2 RCE)",
                "HTTP methods enumeration (OPTIONS, TRACE, etc.)",
                "Clickjacking vulnerability (missing X-Frame-Options)",
                "Missing security headers (CSP, HSTS, etc.)"
            ],
            "HTTP-Alt": [
                "CVE-2021-44228 (Log4Shell - if using vulnerable log4j)",
                "CVE-2022-22965 (Spring4Shell - Spring Framework RCE)",
                "CVE-2017-5638 (Apache Struts2 RCE)",
                "Alternate HTTP port may indicate admin interface",
                "Potential for credential brute forcing",
                "May expose administrative functions"
            ],
            "HTTPS": [
                "CVE-2014-0160 (Heartbleed - OpenSSL vulnerability)",
                "CVE-2014-3566 (POODLE - SSLv3 vulnerability)",
                "CVE-2016-2107 (OpenSSL padding oracle)",
                "CVE-2021-3449 (OpenSSL NULL pointer dereference)",
                "Weak SSL/TLS ciphers (RC4, DES, etc.)",
                "SSL certificate validation issues",
                "TLS downgrade attacks possible"
            ],
            "HTTPS-Alt": [
                "CVE-2014-0160 (Heartbleed - OpenSSL vulnerability)",
                "CVE-2014-3566 (POODLE - SSLv3 vulnerability)",
                "Alternate HTTPS port may indicate admin interface",
                "SSL/TLS configuration vulnerabilities",
                "Certificate validation issues"
            ],
            "DNS": [
                "CVE-2020-1350 (SIGRed - Windows DNS RCE)",
                "CVE-2008-1447 (DNS cache poisoning)",
                "CVE-2015-7547 (glibc DNS resolver vulnerability)",
                "DNS amplification attacks possible",
                "DNS zone transfer may expose information",
                "DNS tunneling for data exfiltration"
            ],
            "SMTP": [
                "CVE-2020-7247 (OpenSMTPD vulnerability)",
                "CVE-2019-19844 (Django email header injection)",
                "Open relay configuration vulnerability",
                "Email spoofing attacks possible",
                "SMTP user enumeration (VRFY, EXPN commands)",
                "Lack of SPF/DKIM/DMARC protection"
            ],
            "POP3": [
                "CVE-2007-1558 (APOP vulnerability)",
                "Unencrypted authentication (USER/PASS)",
                "Plain text email transmission",
                "Password brute force attacks",
                "Email enumeration possible"
            ],
            "IMAP": [
                "CVE-2021-38371 (Dovecot vulnerability)",
                "CVE-2020-12100 (Dovecot RCE)",
                "Unencrypted authentication vulnerability",
                "Plain text email transmission",
                "Email enumeration attacks"
            ],
            "NetBIOS": [
                "CVE-2017-0144 (EternalBlue affects NetBIOS)",
                "NetBIOS name enumeration",
                "SMB relay attacks possible",
                "Null session enumeration",
                "Information disclosure via NetBIOS"
            ],
            "Unknown": [
                "Service fingerprinting recommended",
                "Potential for service-specific vulnerabilities",
                "Banner grabbing may reveal version information",
                "Check for default credentials"
            ]
        }
    
    def save_database(self, db_data: Dict, filename: str = 'enhanced_cve_database.json'):
        """Save enhanced database to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(db_data, f, indent=2)
            print(f"✅ Enhanced CVE database saved to {filename}")
            print(f"📊 Total services: {len(db_data)}")
            print(f"📊 Total vulnerabilities: {sum(len(v) for v in db_data.values())}")
            return True
        except Exception as e:
            print(f"❌ Error saving database: {e}")
            return False

def main():
    updater = VulnerabilityUpdater()
    
    print("🛡️ VULNERABILITY DATABASE UPDATER")
    print("=" * 50)
    
    # Try to fetch live data first
    print("🌐 Attempting to fetch live CVE data...")
    enhanced_db = updater.create_enhanced_database()
    
    # If live data fetch fails or returns empty, use builtin
    if not enhanced_db or sum(len(v) for v in enhanced_db.values()) < 10:
        print("📚 Using comprehensive built-in database...")
        enhanced_db = updater.get_builtin_enhanced_database()
    
    # Save to file
    if updater.save_database(enhanced_db):
        print("\n🎉 Vulnerability database update complete!")
        print("The scanner will now use the enhanced database automatically.")
    else:
        print("\n❌ Failed to save database.")

if __name__ == "__main__":
    main() 