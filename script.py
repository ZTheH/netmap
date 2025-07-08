#!/usr/bin/env python3
"""
Enhanced Network Security Scanner

A comprehensive network security scanner with improved features:
- Host discovery with ping sweep and ARP scanning
- Multi-threaded port scanning with proper cancellation
- Service detection with banner grabbing
- Vulnerability assessment with comprehensive database
- Proper error handling and logging
- Configuration management
- Single host detailed scanning
- Network range scanning with CIDR support
- Professional reporting and JSON export

Author: Enhanced version
"""

import socket
import subprocess
import platform
import threading
import time
import ipaddress
import json
import logging
import signal
import sys
import re
import os
from typing import List, Dict, Set, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from contextlib import contextmanager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Data class to store scan results."""
    host: str
    port: int
    service: str = "Unknown"
    banner: str = ""
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class HostInfo:
    """Data class to store host information."""
    ip: str
    hostname: str = "Unknown"
    mac_address: str = "Unknown"
    vendor: str = "Unknown"
    os_guess: str = "Unknown"
    response_time: float = 0.0
    
    def __str__(self):
        return f"{self.ip} ({self.hostname})"


class NetworkScanner:
    """Enhanced Network Security Scanner with improved features."""
    
    def __init__(self, max_threads: int = 15, timeout: float = 0.5):
        self.max_threads = max_threads
        self.timeout = timeout
        self.interrupted = False
        self.results: List[ScanResult] = []
        self.vulnerability_db = self._load_vulnerability_database()
        self.vendor_db = self._load_vendor_database()
        
        # Set up signal handler for Ctrl+C (only if in main thread)
        try:
            signal.signal(signal.SIGINT, self._signal_handler)
        except ValueError:
            # Signal handler can only be registered from main thread
            # This is expected when called from GUI or other threads
            logger.info("Signal handler not registered (not in main thread)")
        
        # Common ports to scan
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
            993, 995, 3389, 5432, 3306, 1521, 8080, 8443, 9000
        ]
        
        # Service detection patterns
        self.service_patterns = {
            21: ("FTP", b"USER anonymous\r\n"),
            22: ("SSH", b"SSH-2.0-OpenSSH_Test\r\n"),
            23: ("Telnet", b"\r\n"),
            25: ("SMTP", b"EHLO test.com\r\n"),
            53: ("DNS", None),
            80: ("HTTP", b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"),
            110: ("POP3", b"USER test\r\n"),
            135: ("RPC", None),
            139: ("NetBIOS", None),
            143: ("IMAP", b"A001 CAPABILITY\r\n"),
            443: ("HTTPS", b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"),
            445: ("SMB", None),
            993: ("IMAPS", None),
            995: ("POP3S", None),
            3389: ("RDP", None),
            5432: ("PostgreSQL", None),
            3306: ("MySQL", None),
            1521: ("Oracle", None),
            8080: ("HTTP-Alt", b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"),
            8443: ("HTTPS-Alt", b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n"),
            9000: ("HTTP-Alt", b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n")
        }
    
    def _signal_handler(self, signum, frame):
        """Handle Ctrl+C signal."""
        print("\n🛑 Interrupt signal received, cancelling scan...")
        self.interrupted = True
    
    def cancel_scan(self):
        """Cancel the current scan (can be called from any thread)."""
        self.interrupted = True
        logger.info("Scan cancelled externally")
    
    def _load_vulnerability_database(self) -> Dict[str, List[str]]:
        """Load comprehensive vulnerability database from multiple sources."""
        # Try to load from external enhanced database file first
        try:
            if os.path.exists('enhanced_cve_database.json'):
                with open('enhanced_cve_database.json', 'r') as f:
                    external_db = json.load(f)
                    logger.info(f"Loaded enhanced CVE database with {len(external_db)} service categories")
                    return external_db
        except Exception as e:
            logger.debug(f"Could not load enhanced CVE database: {e}")
        
        # Fallback to comprehensive built-in database
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
    
    def _load_vendor_database(self) -> Dict[str, str]:
        """Load MAC address vendor database."""
        return {
            "00:01:02": "3Com", "00:01:03": "3Com", "00:02:A5": "3Com",
            "00:03:47": "Intel", "00:04:AC": "Intel", "00:07:E9": "Intel",
            "00:08:02": "Hewlett-Packard", "00:08:74": "Dell", "00:0A:27": "Apple",
            "00:0B:DB": "Dell", "00:0C:29": "VMware", "00:0D:87": "Cisco",
            "00:0E:58": "Cisco", "00:10:18": "Broadcom", "00:11:43": "Dell",
            "00:12:3F": "Apple", "00:13:72": "Dell", "00:14:22": "Dell",
            "00:15:5D": "Microsoft", "00:16:CB": "Apple", "00:17:A4": "Dell",
            "00:18:8B": "Dell", "00:19:99": "Apple", "00:1A:A0": "Dell",
            "00:1B:21": "Dell", "00:1C:42": "Dell", "00:1D:7E": "Apple",
            "00:1E:52": "Apple", "00:1F:5B": "Apple", "00:20:91": "VIA",
            "00:21:70": "Dell", "00:22:19": "Apple", "00:23:32": "Apple",
            "00:24:36": "Apple", "00:25:00": "Apple", "00:25:4B": "Apple",
            "00:26:08": "Apple", "00:26:BB": "Apple", "00:27:15": "Lenovo",
            "00:50:56": "VMware", "00:A0:C9": "Intel", "00:B0:D0": "Dell",
            "00:C0:B7": "American Megatrends", "00:D0:B7": "Intel",
            "00:E0:81": "Tyan Computer", "08:00:27": "Oracle VirtualBox",
            "50:65:F3": "Cisco", "52:54:00": "QEMU/KVM", "54:52:00": "Realtec",
            "68:05:CA": "Cisco", "70:B3:D5": "IEEE", "78:2B:CB": "Apple",
            "8C:DC:D4": "Apple", "A0:36:9F": "Apple", "A4:5E:60": "Apple",
            "AC:BC:32": "Apple", "B8:E8:56": "Apple", "C8:2A:14": "Apple",
            "DC:A6:32": "Apple", "E0:AC:CB": "Apple", "E4:CE:8F": "Apple",
            "F0:18:98": "Apple", "F4:37:B7": "Apple", "F8:1E:DF": "Apple"
        }
    
    @contextmanager
    def _socket_context(self, host: str, port: int):
        """Context manager for socket connections."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            yield sock
        finally:
            sock.close()
    
    def validate_ip_input(self, target: str) -> List[str]:
        """Validate and parse IP input (single IP or CIDR notation)."""
        targets = []
        try:
            # Try to parse as single IP
            ip = ipaddress.ip_address(target)
            targets.append(str(ip))
        except ValueError:
            try:
                # Try to parse as network (CIDR notation)
                network = ipaddress.ip_network(target, strict=False)
                targets.extend([str(ip) for ip in network.hosts()])
                if len(targets) > 254:
                    logger.warning(f"Large network range detected ({len(targets)} hosts). Consider breaking into smaller ranges.")
            except ValueError:
                raise ValueError(f"Invalid IP address or network: {target}")
        
        return targets
    
    def validate_single_host(self, host: str) -> str:
        """Validate single host input."""
        try:
            # Try to parse as IP address
            ip = ipaddress.ip_address(host)
            return str(ip)
        except ValueError:
            # Could be a hostname, try to resolve
            try:
                resolved_ip = socket.gethostbyname(host)
                return resolved_ip
            except socket.gaierror:
                raise ValueError(f"Invalid host or cannot resolve: {host}")
    
    def ping_host(self, host: str) -> bool:
        """Check if host is alive using ping."""
        try:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", host]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", host]
            
            result = subprocess.run(cmd, capture_output=True, timeout=3)
            return result.returncode == 0
        except:
            return False
    
    def scan_port(self, host: str, port: int) -> Optional[ScanResult]:
        """Scan a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt to connect and send a banner request
            if port in self.service_patterns:
                service_name, banner_pattern = self.service_patterns[port]
                if banner_pattern:
                    try:
                        sock.sendall(banner_pattern)
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        if banner.startswith("220"): # Example banner for SMTP
                            service_name = "SMTP"
                        elif banner.startswith("235"): # Example banner for SMTP
                            service_name = "SMTP"
                    except:
                        banner = ""
                else:
                    banner = ""
            else:
                banner = ""
            
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                service = self._get_service_name(port)
                vulns = self._get_vulnerabilities(port)
                return ScanResult(host=host, port=port, service=service, banner=banner, vulnerabilities=vulns)
        except:
            pass
        return None
    
    def _get_service_name(self, port: int) -> str:
        """Determine service name based on port."""
        if port in self.service_patterns:
            return self.service_patterns[port][0]
        return "Unknown"
    
    def _get_vulnerabilities(self, service: str) -> List[str]:
        """Get vulnerabilities for a service from the database."""
        return self.vulnerability_db.get(service, [])
    
    def discover_hosts(self, network: str) -> List[str]:
        """Discover active hosts in network."""
        try:
            if "/" not in network:
                # Single IP
                return [network] if self.ping_host(network) else []
            
            # CIDR notation
            net = ipaddress.ip_network(network, strict=False)
            hosts = [str(ip) for ip in net.hosts()]
            
            logger.info(f"Discovering hosts in {network}...")
            active_hosts = []
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_host = {executor.submit(self.ping_host, host): host for host in hosts}
                
                for future in as_completed(future_to_host):
                    host = future_to_host[future]
                    if future.result():
                        active_hosts.append(host)
                        logger.info(f"✓ Found: {host}")
            
            return active_hosts
        except Exception as e:
            logger.error(f"Error in host discovery: {e}")
            return []
    
    def scan_host(self, host: str, ports: List[int] = None) -> List[ScanResult]:
        """Scan ports on a single host."""
        if ports is None:
            ports = self.common_ports
        
        logger.info(f"Scanning {host}...")
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {executor.submit(self.scan_port, host, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
                    logger.info(f"✓ {host}:{result.port} ({result.service})")
        
        return open_ports
    
    def scan_network(self, network: str, ports: List[int] = None) -> List[ScanResult]:
        """Scan entire network."""
        # Discover hosts
        hosts = self.discover_hosts(network)
        if not hosts:
            logger.warning("No active hosts found.")
            return []
        
        logger.info(f"Found {len(hosts)} active hosts. Starting port scan...")
        
        # Scan each host
        all_results = []
        for host in hosts:
            results = self.scan_host(host, ports)
            all_results.extend(results)
        
        return all_results
    
    def generate_report(self, results: List[ScanResult]) -> str:
        """Generate simple text report."""
        if not results:
            return "No open ports found."
        
        report = ["SCAN RESULTS", "=" * 50, ""]
        
        # Group by host
        hosts = {}
        for result in results:
            host = result.host
            if host not in hosts:
                hosts[host] = []
            hosts[host].append(result)
        
        # Generate report
        for host, host_results in hosts.items():
            report.append(f"Host: {host}")
            report.append("-" * 30)
            
            for result in host_results:
                report.append(f"  Port {result.port}: {result.service}")
                if result.banner:
                    report.append(f"    • Banner: {result.banner[:100]}...")
                for vuln in result.vulnerabilities:
                    report.append(f"    • {vuln}")
            report.append("")
        
        report.append(f"Summary: {len(results)} open ports found on {len(hosts)} hosts")
        return "\n".join(report)
    
    def save_results(self, results: List[ScanResult], filename: str = "scan_results.json"):
        """Save results to JSON file."""
        result_data = []
        for result in results:
            result_data.append({
                "host": result.host,
                "port": result.port,
                "service": result.service,
                "banner": result.banner,
                "vulnerabilities": result.vulnerabilities
            })
        
        with open(filename, 'w') as f:
            json.dump(result_data, f, indent=2)
        logger.info(f"Results saved to {filename}")
    
    def gather_host_info(self, ip: str) -> HostInfo:
        """Gather detailed information about a host."""
        host_info = HostInfo(ip=ip)
        
        # Get hostname
        try:
            host_info.hostname = socket.gethostbyaddr(ip)[0]
        except:
            host_info.hostname = "Unknown"
        
        # Get MAC address from ARP table
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if ip in line:
                            mac_match = re.search(r'([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})', line)
                            if mac_match:
                                host_info.mac_address = mac_match.group(1).replace('-', ':')
                                # Get vendor info
                                mac_prefix = host_info.mac_address[:8].upper()
                                host_info.vendor = self.vendor_db.get(mac_prefix, "Unknown")
                                break
            else:
                result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if ip in line:
                            mac_match = re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', line)
                            if mac_match:
                                host_info.mac_address = mac_match.group(1)
                                # Get vendor info
                                mac_prefix = host_info.mac_address[:8].upper()
                                host_info.vendor = self.vendor_db.get(mac_prefix, "Unknown")
                                break
        except:
            pass
        
        # Ping for response time and OS guess
        try:
            start_time = time.time()
            if platform.system().lower() == "windows":
                result = subprocess.run(["ping", "-n", "1", ip], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    host_info.response_time = (time.time() - start_time) * 1000
                    # Try to guess OS from TTL
                    ttl_match = re.search(r'TTL=(\d+)', result.stdout)
                    if ttl_match:
                        ttl = int(ttl_match.group(1))
                        if ttl <= 64:
                            host_info.os_guess = "Linux/Unix"
                        elif ttl <= 128:
                            host_info.os_guess = "Windows"
                        else:
                            host_info.os_guess = "Network Device"
            else:
                result = subprocess.run(["ping", "-c", "1", ip], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    host_info.response_time = (time.time() - start_time) * 1000
                    # Try to guess OS from TTL
                    ttl_match = re.search(r'ttl=(\d+)', result.stdout)
                    if ttl_match:
                        ttl = int(ttl_match.group(1))
                        if ttl <= 64:
                            host_info.os_guess = "Linux/Unix"
                        elif ttl <= 128:
                            host_info.os_guess = "Windows"
                        else:
                            host_info.os_guess = "Network Device"
        except:
            pass
        
        return host_info
    
    def discover_hosts_detailed(self, targets: List[str]) -> List[HostInfo]:
        """Discover hosts with detailed information."""
        print(f"🔍 Discovering hosts with detailed information...")
        discovered_hosts = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit ping tasks in batches
            batch_size = 100
            for i in range(0, len(targets), batch_size):
                if self.interrupted:
                    break
                
                batch = targets[i:i + batch_size]
                future_to_host = {executor.submit(self.ping_host, host): host for host in batch}
                
                for future in as_completed(future_to_host):
                    if self.interrupted:
                        break
                    
                    host = future_to_host[future]
                    try:
                        if future.result():
                            print(f"✓ {host} is alive, gathering details...")
                            host_info = self.gather_host_info(host)
                            discovered_hosts.append(host_info)
                            print(f"  📋 {host_info.ip} ({host_info.hostname}) - {host_info.vendor} - {host_info.os_guess}")
                    except Exception as e:
                        logger.error(f"Error checking {host}: {e}")
                
                if not self.interrupted:
                    # Show progress
                    processed = min(i + batch_size, len(targets))
                    print(f"📊 Progress: {processed}/{len(targets)} hosts processed")
        
        return discovered_hosts
    
    def perform_single_host_scan(self, host: str, ports: List[int] = None) -> List[ScanResult]:
        """Perform comprehensive scan on a single host with progress tracking."""
        if ports is None:
            ports = self.common_ports
        
        print(f"🎯 Scanning {host} on {len(ports)} ports...")
        
        results = []
        completed = 0
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit port scans in batches for responsiveness
            batch_size = 100
            for i in range(0, len(ports), batch_size):
                if self.interrupted:
                    print(f"\n🛑 Scan interrupted! Preserving {len(results)} results found so far.")
                    break
                
                batch = ports[i:i + batch_size]
                future_to_port = {executor.submit(self.scan_port, host, port): port for port in batch}
                
                for future in as_completed(future_to_port):
                    if self.interrupted:
                        future.cancel()
                        break
                    
                    port = future_to_port[future]
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                            print(f"✅ {host}:{result.port} ({result.service})")
                            if result.banner:
                                print(f"   🏷️  Banner: {result.banner[:100]}...")
                        
                        completed += 1
                        
                        # Update progress every 10 ports
                        if completed % 10 == 0:
                            elapsed = time.time() - start_time
                            rate = completed / elapsed if elapsed > 0 else 0
                            remaining = len(ports) - completed
                            eta = remaining / rate if rate > 0 else 0
                            print(f"⏳ Progress: {completed}/{len(ports)} ports ({rate:.1f} ports/sec, ETA: {eta:.1f}s)")
                    
                    except Exception as e:
                        logger.error(f"Error scanning {host}:{port}: {e}")
                    
                    # Check for interruption frequently
                    if self.interrupted:
                        break
                
                time.sleep(0.1)  # Brief pause to allow interrupt checking
        
        elapsed = time.time() - start_time
        print(f"✅ Scan completed in {elapsed:.2f} seconds")
        print(f"📊 Found {len(results)} open ports on {host}")
        
        return results
    
    def perform_port_scan(self, hosts: List[str], ports: List[int] = None) -> List[ScanResult]:
        """Perform port scan on multiple hosts with progress tracking."""
        if ports is None:
            ports = self.common_ports
        
        total_targets = len(hosts) * len(ports)
        print(f"🚀 Starting port scan on {len(hosts)} hosts, {len(ports)} ports per host ({total_targets} total connections)")
        
        results = []
        completed = 0
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all scan tasks
            futures = []
            for host in hosts:
                for port in ports:
                    if self.interrupted:
                        break
                    future = executor.submit(self.scan_port, host, port)
                    futures.append((future, host, port))
            
            # Process results as they complete
            for future, host, port in futures:
                if self.interrupted:
                    future.cancel()
                    break
                
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        print(f"✅ {host}:{port} ({result.service})")
                        if result.banner:
                            print(f"   🏷️  Banner: {result.banner[:100]}...")
                    
                    completed += 1
                    
                    # Update progress every 50 completed scans
                    if completed % 50 == 0:
                        elapsed = time.time() - start_time
                        rate = completed / elapsed if elapsed > 0 else 0
                        remaining = total_targets - completed
                        eta = remaining / rate if rate > 0 else 0
                        print(f"⏳ Progress: {completed}/{total_targets} ({rate:.1f} scans/sec, ETA: {eta:.1f}s)")
                
                except Exception as e:
                    logger.error(f"Error scanning {host}:{port}: {e}")
                
                # Check for interruption frequently
                if self.interrupted:
                    print(f"\n🛑 Scan interrupted! Preserving {len(results)} results found so far.")
                    break
        
        elapsed = time.time() - start_time
        print(f"✅ Scan completed in {elapsed:.2f} seconds")
        print(f"📊 Found {len(results)} open ports across {len(hosts)} hosts")
        
        return results
    
    def grab_banner(self, host: str, port: int) -> str:
        """Grab banner from a service."""
        try:
            with self._socket_context(host, port) as sock:
                result = sock.connect_ex((host, port))
                if result != 0:
                    return ""
                
                # Send appropriate request based on service
                if port in self.service_patterns:
                    service_name, request = self.service_patterns[port]
                    if request:
                        sock.send(request)
                
                # Try to receive banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner
        except Exception as e:
            logger.debug(f"Banner grab failed for {host}:{port}: {e}")
            return ""
    
    def _identify_service_from_banner(self, banner: str) -> str:
        """Identify service from banner string."""
        banner_lower = banner.lower()
        
        if "apache" in banner_lower:
            return "Apache HTTP Server"
        elif "nginx" in banner_lower:
            return "Nginx HTTP Server"
        elif "microsoft-iis" in banner_lower:
            return "Microsoft IIS"
        elif "openssh" in banner_lower:
            return "OpenSSH"
        elif "vsftpd" in banner_lower:
            return "vsftpd FTP Server"
        elif "mysql" in banner_lower:
            return "MySQL Database"
        elif "postgresql" in banner_lower:
            return "PostgreSQL Database"
        elif "microsoft-ds" in banner_lower:
            return "Microsoft Directory Services"
        elif "smtp" in banner_lower:
            return "SMTP Mail Server"
        elif "pop3" in banner_lower:
            return "POP3 Mail Server"
        elif "imap" in banner_lower:
            return "IMAP Mail Server"
        elif "telnet" in banner_lower:
            return "Telnet Server"
        elif "ftp" in banner_lower:
            return "FTP Server"
        elif "dns" in banner_lower:
            return "DNS Server"
        elif "dhcp" in banner_lower:
            return "DHCP Server"
        elif "snmp" in banner_lower:
            return "SNMP Agent"
        elif "rdp" in banner_lower or "terminal" in banner_lower:
            return "Remote Desktop Protocol"
        elif "http" in banner_lower:
            return "HTTP Server"
        else:
            return "Unknown Service"
    
    def assess_vulnerabilities(self, scan_results: List[ScanResult]) -> List[ScanResult]:
        """Assess vulnerabilities for scan results."""
        for result in scan_results:
            # Check banner against vulnerability database
            if result.banner:
                for vuln_service, vulns in self.vulnerability_db.items():
                    if vuln_service.lower() in result.banner.lower():
                        result.vulnerabilities.extend(vulns)
            
            # Check service-specific vulnerabilities
            if result.service in self.vulnerability_db:
                result.vulnerabilities.extend(self.vulnerability_db[result.service])
        
        return scan_results
    
    def generate_professional_report(self, scan_results: List[ScanResult], host_info: List[HostInfo] = None) -> str:
        """Generate a professional security assessment report."""
        report = []
        
        # Header
        report.append("🛡️  NETWORK SECURITY ASSESSMENT REPORT")
        report.append("=" * 60)
        report.append(f"📅 Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"🎯 Targets Scanned: {len(set(r.host for r in scan_results))}")
        report.append(f"🔍 Total Open Ports: {len(scan_results)}")
        report.append("")
        
        # Executive Summary
        report.append("📋 EXECUTIVE SUMMARY")
        report.append("-" * 30)
        if scan_results:
            critical_services = [r for r in scan_results if any("Critical" in v for v in r.vulnerabilities)]
            high_risk_ports = [r for r in scan_results if r.port in [21, 23, 135, 139, 445]]
            
            report.append(f"• {len(critical_services)} services with critical vulnerabilities found")
            report.append(f"• {len(high_risk_ports)} high-risk services identified")
            report.append(f"• {len(scan_results)} total open ports discovered")
        else:
            report.append("• No open ports discovered during scan")
        report.append("")
        
        # Host Information
        if host_info:
            report.append("🖥️  HOST INFORMATION")
            report.append("-" * 30)
            for info in host_info:
                report.append(f"Host: {info.ip}")
                report.append(f"  Hostname: {info.hostname}")
                report.append(f"  MAC Address: {info.mac_address}")
                report.append(f"  Vendor: {info.vendor}")
                report.append(f"  OS Guess: {info.os_guess}")
                report.append(f"  Response Time: {info.response_time:.2f}ms")
                report.append("")
        
        # Detailed Findings
        if scan_results:
            report.append("🔍 DETAILED FINDINGS")
            report.append("-" * 30)
            
            # Group by host
            hosts = {}
            for result in scan_results:
                if result.host not in hosts:
                    hosts[result.host] = []
                hosts[result.host].append(result)
            
            for host, host_results in hosts.items():
                report.append(f"🎯 Host: {host}")
                report.append("  " + "-" * 40)
                
                for result in host_results:
                    report.append(f"  🔌 Port {result.port}: {result.service}")
                    
                    if result.banner:
                        report.append(f"    📋 Banner: {result.banner[:100]}...")
                    
                    if result.vulnerabilities:
                        report.append("    ⚠️  Vulnerabilities:")
                        for vuln in result.vulnerabilities:
                            if "Critical" in vuln:
                                report.append(f"      🔴 {vuln}")
                            elif "High" in vuln:
                                report.append(f"      🟠 {vuln}")
                            else:
                                report.append(f"      🟡 {vuln}")
                    else:
                        report.append("    ✅ No known vulnerabilities")
                    
                    report.append("")
        
        # Recommendations
        report.append("💡 RECOMMENDATIONS")
        report.append("-" * 30)
        if scan_results:
            report.append("• Review and secure all open ports")
            report.append("• Update services with known vulnerabilities")
            report.append("• Consider implementing network segmentation")
            report.append("• Regular security assessments recommended")
        else:
            report.append("• No immediate security concerns identified")
            report.append("• Continue regular security monitoring")
        report.append("")
        
        # Footer
        report.append("=" * 60)
        report.append("Report generated by Enhanced Network Security Scanner")
        
        return "\n".join(report)


def get_top_1000_ports() -> List[int]:
    """Return list of top 1000 most common ports."""
    return list(range(1, 1001))


def get_target_input() -> str:
    """Get target input from user."""
    while True:
        target = input("\n🎯 Enter target (IP address or network in CIDR notation): ").strip()
        if target:
            return target
        print("❌ Please enter a valid target.")


def get_single_host_input() -> str:
    """Get single host input from user."""
    while True:
        host = input("\n🎯 Enter host (IP address or hostname): ").strip()
        if host:
            return host
        print("❌ Please enter a valid host.")


def get_scan_options() -> Dict[str, any]:
    """Get scan options from user."""
    print("\n🔧 SCAN OPTIONS")
    print("=" * 30)
    print("1. 🚀 Network Discovery + Port Scan")
    print("2. 🔍 Network Discovery Only")
    print("3. 🎯 Single Host Detailed Scan")
    print("4. ❌ Exit")
    
    while True:
        choice = input("\n📋 Select option (1-4): ").strip()
        if choice in ["1", "2", "3", "4"]:
            return {"choice": choice}
        print("❌ Please enter a valid option (1-4).")


def get_network_scan_options() -> Dict[str, any]:
    """Get network scan options from user."""
    print("\n🔧 PORT SCAN OPTIONS")
    print("=" * 30)
    print("1. ⚡ Common ports (fast)")
    print("2. 🔍 Top 1000 ports")
    print("3. 🎯 Custom port range")
    print("4. 📝 Specific ports")
    
    while True:
        choice = input("\n📋 Select scan type (1-4): ").strip()
        if choice == "1":
            return {"scan_type": "common"}
        elif choice == "2":
            return {"scan_type": "top1000"}
        elif choice == "3":
            start = input("Enter start port: ").strip()
            end = input("Enter end port: ").strip()
            try:
                start_port = int(start)
                end_port = int(end)
                if 1 <= start_port <= end_port <= 65535:
                    return {"scan_type": "range", "start": start_port, "end": end_port}
                else:
                    print("❌ Invalid port range. Please use ports 1-65535.")
            except ValueError:
                print("❌ Please enter valid port numbers.")
        elif choice == "4":
            ports_input = input("Enter ports separated by commas (e.g., 80,443,22): ").strip()
            try:
                ports = [int(p.strip()) for p in ports_input.split(",")]
                if all(1 <= p <= 65535 for p in ports):
                    return {"scan_type": "custom", "ports": ports}
                else:
                    print("❌ Invalid port numbers. Please use ports 1-65535.")
            except ValueError:
                print("❌ Please enter valid port numbers.")
        else:
            print("❌ Please enter a valid option (1-4).")


def get_single_host_scan_options() -> Dict[str, any]:
    """Get single host scan options from user."""
    print("\n🔧 SINGLE HOST SCAN OPTIONS")
    print("=" * 30)
    print("1. ⚡ Common ports (21 ports)")
    print("2. 🔍 Top 1000 ports")
    print("3. 🎯 Full port scan (1-65535) ⚠️  VERY SLOW")
    print("4. 📝 Custom port range")
    print("5. 🎪 Specific ports")
    
    while True:
        choice = input("\n📋 Select scan type (1-5): ").strip()
        if choice == "1":
            return {"scan_type": "common"}
        elif choice == "2":
            return {"scan_type": "top1000"}
        elif choice == "3":
            confirm = input("⚠️  Full scan can take 30+ minutes. Continue? (y/N): ").strip().lower()
            if confirm == 'y':
                return {"scan_type": "full"}
            else:
                print("🔄 Please select another option.")
        elif choice == "4":
            start = input("Enter start port: ").strip()
            end = input("Enter end port: ").strip()
            try:
                start_port = int(start)
                end_port = int(end)
                if 1 <= start_port <= end_port <= 65535:
                    port_count = end_port - start_port + 1
                    if port_count > 1000:
                        print(f"⚠️  You're about to scan {port_count} ports. This may take a while.")
                        confirm = input("Continue? (y/N): ").strip().lower()
                        if confirm != 'y':
                            print("🔄 Please select another option.")
                            continue
                    return {"scan_type": "range", "start": start_port, "end": end_port}
                else:
                    print("❌ Invalid port range. Please use ports 1-65535.")
            except ValueError:
                print("❌ Please enter valid port numbers.")
        elif choice == "5":
            ports_input = input("Enter ports separated by commas (e.g., 80,443,22): ").strip()
            try:
                ports = [int(p.strip()) for p in ports_input.split(",")]
                if all(1 <= p <= 65535 for p in ports):
                    return {"scan_type": "custom", "ports": ports}
                else:
                    print("❌ Invalid port numbers. Please use ports 1-65535.")
            except ValueError:
                print("❌ Please enter valid port numbers.")
        else:
            print("❌ Please enter a valid option (1-5).")


def main():
    """Main function with enhanced user interface."""
    print("🛡️  ENHANCED NETWORK SECURITY SCANNER")
    print("=" * 50)
    print("Advanced network reconnaissance and security assessment tool")
    print("Features: Host discovery, port scanning, service detection, vulnerability assessment")
    print()
    
    scanner = NetworkScanner()
    
    try:
        while True:
            options = get_scan_options()
            
            if options["choice"] == "4":
                print("👋 Goodbye!")
                break
            elif options["choice"] == "1":
                # Network Discovery + Port Scan
                target = get_target_input()
                
                try:
                    targets = scanner.validate_ip_input(target)
                    print(f"🎯 Validated {len(targets)} targets")
                    
                    if len(targets) > 50:
                        print(f"⚠️  Large target range ({len(targets)} hosts). This may take a while.")
                        confirm = input("Continue? (y/N): ").strip().lower()
                        if confirm != 'y':
                            continue
                    
                    scan_options = get_network_scan_options()
                    
                    # Determine ports to scan
                    if scan_options["scan_type"] == "common":
                        ports = scanner.common_ports
                    elif scan_options["scan_type"] == "top1000":
                        ports = get_top_1000_ports()
                    elif scan_options["scan_type"] == "range":
                        ports = list(range(scan_options["start"], scan_options["end"] + 1))
                    elif scan_options["scan_type"] == "custom":
                        ports = scan_options["ports"]
                    
                    print(f"\n🚀 Starting comprehensive scan...")
                    print(f"📊 Targets: {len(targets)}, Ports per target: {len(ports)}")
                    start_time = time.time()
                    
                    # Discover hosts with details
                    host_info = scanner.discover_hosts_detailed(targets)
                    
                    if not host_info:
                        print("❌ No active hosts found.")
                        continue
                    
                    # Perform port scan
                    active_hosts = [info.ip for info in host_info]
                    results = scanner.perform_port_scan(active_hosts, ports)
                    
                    # Assess vulnerabilities
                    results = scanner.assess_vulnerabilities(results)
                    
                    elapsed = time.time() - start_time
                    
                    print(f"\n✅ Scan completed in {elapsed:.2f} seconds")
                    print(f"📊 Results: {len(results)} open ports found")
                    
                    # Generate and display report
                    if results or host_info:
                        report = scanner.generate_professional_report(results, host_info)
                        print("\n" + report)
                        
                        # Save results
                        save_choice = input("\n💾 Save results to file? (y/N): ").strip().lower()
                        if save_choice == 'y':
                            scanner.save_results(results, f"scan_results_{int(time.time())}.json")
                            
                            # Save host info
                            if host_info:
                                host_data = []
                                for info in host_info:
                                    host_data.append({
                                        "ip": info.ip,
                                        "hostname": info.hostname,
                                        "mac_address": info.mac_address,
                                        "os_guess": info.os_guess,
                                        "response_time": info.response_time
                                    })
                                
                                with open(f"host_discovery_{int(time.time())}.json", 'w') as f:
                                    json.dump(host_data, f, indent=2)
                                print(f"📋 Host discovery results saved to host_discovery_{int(time.time())}.json")
                    else:
                        print("❌ No results to display.")
                    
                except ValueError as e:
                    print(f"❌ Error: {e}")
                except Exception as e:
                    print(f"❌ Unexpected error: {e}")
                    
            elif options["choice"] == "2":
                # Network Discovery Only
                target = get_target_input()
                
                try:
                    targets = scanner.validate_ip_input(target)
                    print(f"🎯 Validated {len(targets)} targets for discovery")
                    
                    start_time = time.time()
                    host_info = scanner.discover_hosts_detailed(targets)
                    elapsed = time.time() - start_time
                    
                    print(f"\n✅ Discovery completed in {elapsed:.2f} seconds")
                    print(f"📊 Found {len(host_info)} active hosts")
                    
                    if host_info:
                        print("\n🖥️  DISCOVERED HOSTS")
                        print("=" * 50)
                        for info in host_info:
                            print(f"🎯 {info.ip}")
                            print(f"  📝 Hostname: {info.hostname}")
                            print(f"  🔧 MAC Address: {info.mac_address}")
                            print(f"  🏢 Vendor: {info.vendor}")
                            print(f"  💻 OS Guess: {info.os_guess}")
                            print(f"  ⏱️  Response Time: {info.response_time:.2f}ms")
                            print()
                        
                        # Save option
                        save_choice = input("💾 Save discovery results to file? (y/N): ").strip().lower()
                        if save_choice == 'y':
                            host_data = []
                            for info in host_info:
                                host_data.append({
                                    "ip": info.ip,
                                    "hostname": info.hostname,
                                    "mac_address": info.mac_address,
                                    "vendor": info.vendor,
                                    "os_guess": info.os_guess,
                                    "response_time": info.response_time
                                })
                            
                            filename = f"host_discovery_{int(time.time())}.json"
                            with open(filename, 'w') as f:
                                json.dump(host_data, f, indent=2)
                            print(f"📋 Discovery results saved to {filename}")
                    else:
                        print("❌ No active hosts found.")
                        
                except ValueError as e:
                    print(f"❌ Error: {e}")
                except Exception as e:
                    print(f"❌ Unexpected error: {e}")
                    
            elif options["choice"] == "3":
                # Single Host Detailed Scan
                host = get_single_host_input()
                
                try:
                    validated_host = scanner.validate_single_host(host)
                    print(f"🎯 Validated target: {validated_host}")
                    
                    scan_options = get_single_host_scan_options()
                    
                    # Determine ports to scan
                    if scan_options["scan_type"] == "common":
                        ports = scanner.common_ports
                    elif scan_options["scan_type"] == "top1000":
                        ports = get_top_1000_ports()
                    elif scan_options["scan_type"] == "full":
                        ports = list(range(1, 65536))
                    elif scan_options["scan_type"] == "range":
                        ports = list(range(scan_options["start"], scan_options["end"] + 1))
                    elif scan_options["scan_type"] == "custom":
                        ports = scan_options["ports"]
                    
                    print(f"\n🚀 Starting detailed scan of {validated_host}")
                    print(f"📊 Scanning {len(ports)} ports...")
                    start_time = time.time()
                    
                    # Gather host information
                    host_info = scanner.gather_host_info(validated_host)
                    print(f"📋 Host Info: {host_info.hostname} - {host_info.vendor} - {host_info.os_guess}")
                    
                    # Perform port scan
                    results = scanner.perform_single_host_scan(validated_host, ports)
                    
                    # Assess vulnerabilities
                    results = scanner.assess_vulnerabilities(results)
                    
                    elapsed = time.time() - start_time
                    
                    print(f"\n✅ Scan completed in {elapsed:.2f} seconds")
                    print(f"📊 Results: {len(results)} open ports found")
                    
                    # Generate and display report
                    if results:
                        report = scanner.generate_professional_report(results, [host_info])
                        print("\n" + report)
                        
                        # Save results
                        save_choice = input("\n💾 Save results to file? (y/N): ").strip().lower()
                        if save_choice == 'y':
                            scanner.save_results(results, f"single_host_scan_{validated_host.replace('.', '_')}_{int(time.time())}.json")
                    else:
                        print("❌ No open ports found.")
                        
                except ValueError as e:
                    print(f"❌ Error: {e}")
                except Exception as e:
                    print(f"❌ Unexpected error: {e}")
                    
    except KeyboardInterrupt:
        print("\n\n🛑 Scan interrupted by user. Goodbye!")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        logger.error(f"Unexpected error in main: {e}")


if __name__ == "__main__":
    main()