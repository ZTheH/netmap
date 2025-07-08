# 🛡️ Enhanced Network Security Scanner

A comprehensive network security scanner with advanced vulnerability detection, modern GUI interface, and extensive CVE database integration.

## ✨ Key Features

### 🔍 **Comprehensive Scanning**
- **Host Discovery**: Ping sweep and ARP scanning for network enumeration
- **Port Scanning**: Multi-threaded scanning with configurable timeouts
- **Service Detection**: Banner grabbing and service fingerprinting
- **Vulnerability Assessment**: Extensive CVE database with 500+ vulnerabilities
- **Network Range Support**: CIDR notation and single host scanning

### 🎨 **Modern GUI Interface**
- **Dark Theme**: Professional teal color scheme (#0d7377)
- **Real-time Progress**: Detailed progress tracking with percentage display
- **Interactive Results**: Expandable vulnerability details
- **Export Options**: Professional PDF reports and JSON export
- **Responsive Design**: Modern fonts and hover effects

### 🔒 **Enhanced Security Features**
- **Live CVE Integration**: Fetches latest vulnerabilities from multiple sources
- **Comprehensive Database**: 500+ CVEs across major services
- **Critical Vulnerability Highlighting**: EternalBlue, BlueKeep, Log4Shell, etc.
- **Service-Specific Assessments**: Tailored vulnerability checks per service
- **Professional Reporting**: Detailed security assessment reports

## 🚀 Quick Start

### Option 1: Simple Launcher
```bash
python launcher.py
```
Choose between CLI or GUI interface from the menu.

### Option 2: Direct CLI Usage
```bash
python script.py
```

### Option 3: Direct GUI Usage
```bash
python scanner_gui.py
```

## 📁 File Structure

```
pfe/
├── launcher.py              # Main launcher with CLI/GUI options
├── script.py               # CLI network scanner (stable)
├── script_gui.py           # GUI-compatible backend
├── scanner_gui.py          # Modern GUI frontend
├── vuln_updater.py         # Vulnerability database updater
├── enhanced_cve_database.json  # Enhanced CVE database
├── network_scanner.log     # Application logs
└── README.md              # This documentation
```

## 🛠️ Installation & Requirements

### Prerequisites
```bash
pip install requests  # For vulnerability updates
```

### Python Requirements
- Python 3.7+
- tkinter (usually included with Python)
- Standard library modules: socket, threading, json, etc.

### Platform Support
- ✅ Windows 10/11
- ✅ Linux (Ubuntu, CentOS, etc.)
- ✅ macOS

## 🔧 Usage Examples

### CLI Interface
```bash
# Network scan with CIDR notation
python script.py
# Enter: 192.168.1.0/24

# Single host detailed scan
python script.py
# Choose option 2, enter: 192.168.1.1

# Custom port range
python script.py
# Configure ports: 1-1000 or specific ports: 22,80,443
```

### GUI Interface
1. Launch GUI: `python scanner_gui.py`
2. Enter target (IP or CIDR): `192.168.1.0/24`
3. Select scan type: Network or Single Host
4. Configure options and click "Start Scan"
5. View real-time progress and results
6. Export reports as needed

## 🔍 Vulnerability Database

### Built-in Coverage
- **Web Services**: Apache, nginx, IIS (100+ CVEs)
- **SSH Services**: OpenSSH versions (50+ CVEs)
- **Database Services**: MySQL, PostgreSQL (40+ CVEs)
- **Windows Services**: SMB, RDP, NetBIOS (30+ CVEs)
- **Network Services**: DNS, SMTP, FTP, Telnet (50+ CVEs)

### Critical Vulnerabilities Detected
- **EternalBlue** (CVE-2017-0144): SMBv1 RCE
- **BlueKeep** (CVE-2019-0708): RDP RCE
- **Log4Shell** (CVE-2021-44228): Log4j RCE
- **Spring4Shell** (CVE-2022-22965): Spring Framework RCE
- **Heartbleed** (CVE-2014-0160): OpenSSL vulnerability
- **POODLE** (CVE-2014-3566): SSLv3 vulnerability

### Database Updates
```bash
# Update vulnerability database
python vuln_updater.py
```

The updater fetches CVE data from:
- **CIRCL Vulnerability-Lookup API**
- **GitHub Security Advisories**
- **NVD (NIST) Database**
- **Built-in comprehensive database**

## 📊 Features Comparison

| Feature | CLI Version | GUI Version |
|---------|-------------|-------------|
| Host Discovery | ✅ | ✅ |
| Port Scanning | ✅ | ✅ |
| Service Detection | ✅ | ✅ |
| Vulnerability Assessment | ✅ | ✅ |
| Real-time Progress | ⚠️ Basic | ✅ Advanced |
| Export Options | ✅ JSON | ✅ JSON + PDF |
| Visual Interface | ❌ | ✅ |
| Scan Cancellation | ✅ | ✅ |
| Professional Reports | ✅ | ✅ |

## 🎯 Advanced Configuration

### Threading Configuration
```python
# Adjust thread count for performance
scanner = NetworkScanner(max_threads=20, timeout=1.0)
```

### Custom Port Lists
```python
# Define custom port ranges
custom_ports = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 3389]
```

### Vulnerability Database Customization
```python
# Add custom vulnerabilities
custom_vulns = {
    "CustomService": [
        "CVE-XXXX-XXXX (Custom vulnerability description)"
    ]
}
```

## 📈 Performance Optimization

### For Large Networks
- Use smaller CIDR ranges (/26 instead of /24)
- Reduce thread count for stability
- Increase timeout for slow networks

### For Fast Networks
- Increase thread count (up to 50)
- Reduce timeout (0.3-0.5 seconds)
- Use top 1000 ports for comprehensive scanning

## 🔐 Security Considerations

### Ethical Usage
- ⚠️ **Only scan networks you own or have explicit permission to test**
- 🚫 **Do not use for unauthorized network reconnaissance**
- ✅ **Ideal for internal security assessments and penetration testing**

### Network Impact
- Scanning generates network traffic
- May trigger security monitoring systems
- Use responsibly in production environments

## 🐛 Troubleshooting

### Common Issues

**"Signal only works in main thread" Error**
- Solution: Use `script_gui.py` instead of `script.py` for GUI integration

**Encoding Error in launcher.py**
- Solution: Ensure file is saved with UTF-8 encoding

**No vulnerabilities found**
- Solution: Run `python vuln_updater.py` to refresh database

**Slow scanning performance**
- Solution: Reduce thread count or increase timeout values

### Debug Mode
```bash
# Enable debug logging
export PYTHONPATH=.
python -c "import logging; logging.basicConfig(level=logging.DEBUG)"
python script.py
```

## 📝 Version History

### v3.0 (Current) - Enhanced Security Scanner
- ✅ Comprehensive CVE database (500+ vulnerabilities)
- ✅ Modern GUI with dark theme
- ✅ Real-time progress tracking
- ✅ Live vulnerability updates
- ✅ Professional reporting
- ✅ Enhanced service detection

### v2.0 - GUI Integration
- ✅ Tkinter GUI interface
- ✅ Threading improvements
- ✅ Signal handler fixes

### v1.0 - CLI Foundation
- ✅ Basic network scanning
- ✅ Port scanning capabilities
- ✅ JSON export functionality

## 🤝 Contributing

Contributions are welcome! Please focus on:
- Additional vulnerability signatures
- Performance optimizations
- New service detection patterns
- GUI enhancements
- Documentation improvements

## 📜 License

This project is for educational and authorized security testing purposes only. Users are responsible for complying with applicable laws and regulations.

## 🔗 Resources

- [NIST National Vulnerability Database](https://nvd.nist.gov/)
- [CIRCL Vulnerability Lookup](https://vulnerability.circl.lu/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Nmap Service Detection](https://nmap.org/book/vscan.html)

---

**⚠️ Disclaimer**: This tool is intended for authorized security testing and educational purposes only. Always ensure you have explicit permission before scanning networks that you do not own. 