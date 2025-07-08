#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import time
import json
import os
import sys
from typing import List, Dict, Optional
from datetime import datetime

try:
    from script_gui import NetworkScannerGUI as NetworkScanner, ScanResult, HostInfo, get_top_1000_ports
except ImportError:
    print('Error: Could not import from script_gui.py')
    sys.exit(1)

class NetworkScannerGUI:
    def __init__(self):
        self.scanner = NetworkScanner(max_threads=15, timeout=1)
        self.scan_thread = None
        self.scan_results = []
        self.host_results = []
        self.is_scanning = False
        self.total_targets = 0
        self.completed_targets = 0
        self.setup_gui()
        
    def setup_gui(self):
        self.root = tk.Tk()
        self.root.title('🛡️ Network Security Scanner - Enhanced CVE Detection')
        self.root.geometry('1200x800')
        self.root.configure(bg='#1a1a1a')
        self.create_widgets()
        
    def create_widgets(self):
        # Configure style with modern colors
        style = ttk.Style()
        style.theme_use('clam')
        
        # Dark theme colors
        style.configure('TFrame', background='#1a1a1a')
        style.configure('TLabel', background='#1a1a1a', foreground='#e0e0e0', font=('Segoe UI', 10))
        style.configure('TButton', 
                       background='#0d7377', 
                       foreground='white', 
                       font=('Segoe UI', 10, 'bold'),
                       borderwidth=0,
                       focuscolor='none')
        style.map('TButton',
                 background=[('active', '#14a085'), ('pressed', '#0a5d61')])
        
        # Entry styling
        style.configure('TEntry', 
                       background='#2d2d2d', 
                       foreground='white',
                       fieldbackground='#2d2d2d',
                       borderwidth=1,
                       insertcolor='white')
        
        # Combobox styling
        style.configure('TCombobox',
                       background='#2d2d2d',
                       foreground='white',
                       fieldbackground='#2d2d2d',
                       borderwidth=1,
                       selectbackground='#0d7377',
                       selectforeground='white')
        style.map('TCombobox',
                 fieldbackground=[('readonly', '#2d2d2d')],
                 selectbackground=[('readonly', '#0d7377')],
                 foreground=[('readonly', 'white')])
        
        # Progress bar styling
        style.configure('TProgressbar',
                       background='#0d7377',
                       troughcolor='#2d2d2d',
                       borderwidth=0,
                       lightcolor='#0d7377',
                       darkcolor='#0d7377')
        
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        title_label = ttk.Label(main_frame, text='🛡️ Network Security Scanner - Enhanced CVE Detection', font=('Segoe UI', 18, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # Input frame
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill='x', padx=20, pady=15)
        
        ttk.Label(input_frame, text='🎯 Target IP/Range:', font=('Segoe UI', 11, 'bold')).pack(side='left', padx=5)
        self.target_entry = ttk.Entry(input_frame, width=40, font=('Segoe UI', 10))
        self.target_entry.pack(side='left', padx=5)
        self.target_entry.insert(0, "192.168.1.0/24")  # Default value
        
        ttk.Label(input_frame, text='⚙️ Scan Type:', font=('Segoe UI', 11, 'bold')).pack(side='left', padx=(20, 5))
        self.scan_type_var = tk.StringVar(value='network_quick')
        scan_types = ['network_quick', 'single_host', 'host_discovery']
        self.scan_type_combo = ttk.Combobox(input_frame, values=scan_types, textvariable=self.scan_type_var, state='readonly', font=('Segoe UI', 10))
        self.scan_type_combo.pack(side='left', padx=5)
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(pady=15)
        
        self.start_button = ttk.Button(buttons_frame, text='🚀 Start Scan', command=self.start_scan)
        self.start_button.pack(side='left', padx=10)
        
        self.stop_button = ttk.Button(buttons_frame, text='🛑 Stop Scan', command=self.stop_scan, state='disabled')
        self.stop_button.pack(side='left', padx=10)
        
        # Progress frame
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill='x', padx=20, pady=10)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100, length=400)
        self.progress_bar.pack(pady=(0, 5))
        
        # Progress percentage label
        self.progress_label = ttk.Label(progress_frame, text='0%', font=('Segoe UI', 10, 'bold'))
        self.progress_label.pack()
        
        self.status_label = ttk.Label(main_frame, text='Ready to scan', font=('Segoe UI', 11))
        self.status_label.pack(pady=5)
        
        # Results display
        results_label = ttk.Label(main_frame, text='📊 Scan Results', font=('Segoe UI', 12, 'bold'))
        results_label.pack(pady=(10, 5))
        
        self.results_text = scrolledtext.ScrolledText(main_frame, height=20, 
                                                    bg='#0f0f0f', fg='#e0e0e0',
                                                    font=('Consolas', 9),
                                                    insertbackground='white',
                                                    selectbackground='#0d7377')
        self.results_text.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Configure color tags for vulnerability severity
        self.configure_vulnerability_colors()
        
        # Add vulnerability color legend
        legend_frame = ttk.Frame(main_frame)
        legend_frame.pack(fill='x', padx=20, pady=5)
        
        ttk.Label(legend_frame, text='🎨 Vulnerability Severity Colors:', font=('Segoe UI', 10, 'bold')).pack(side='left')
        ttk.Label(legend_frame, text='🔴 Critical', foreground='#ff4444', font=('Segoe UI', 9, 'bold')).pack(side='left', padx=10)
        ttk.Label(legend_frame, text='🟠 High', foreground='#ff8800', font=('Segoe UI', 9, 'bold')).pack(side='left', padx=10)
        ttk.Label(legend_frame, text='🟡 Medium', foreground='#ffdd00', font=('Segoe UI', 9, 'bold')).pack(side='left', padx=10)
        ttk.Label(legend_frame, text='🟢 Low', foreground='#44ff44', font=('Segoe UI', 9, 'bold')).pack(side='left', padx=10)
        ttk.Label(legend_frame, text='⚪ Info', foreground='#888888', font=('Segoe UI', 9, 'bold')).pack(side='left', padx=10)
        
        # Export frame
        export_frame = ttk.Frame(main_frame)
        export_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Button(export_frame, text='💾 Export JSON', command=self.export_json).pack(side='left', padx=5)
        ttk.Button(export_frame, text='📄 Export TXT', command=self.export_txt).pack(side='left', padx=5)
    
    def configure_vulnerability_colors(self):
        """Configure text tags for different vulnerability severity levels."""
        # Critical vulnerabilities (red)
        self.results_text.tag_configure('critical', foreground='#ff4444', font=('Consolas', 9, 'bold'))
        
        # High severity vulnerabilities (orange)
        self.results_text.tag_configure('high', foreground='#ff8800', font=('Consolas', 9, 'bold'))
        
        # Medium severity vulnerabilities (yellow)
        self.results_text.tag_configure('medium', foreground='#ffdd00', font=('Consolas', 9, 'bold'))
        
        # Low severity vulnerabilities (green)
        self.results_text.tag_configure('low', foreground='#44ff44', font=('Consolas', 9))
        
        # Info/general vulnerabilities (gray)
        self.results_text.tag_configure('info', foreground='#888888', font=('Consolas', 9))
        
        # No vulnerabilities (bright green)
        self.results_text.tag_configure('secure', foreground='#00ff88', font=('Consolas', 9, 'bold'))
        
        # Headers and important text
        self.results_text.tag_configure('header', foreground='#00ccff', font=('Consolas', 10, 'bold'))
        self.results_text.tag_configure('host', foreground='#ffcc00', font=('Consolas', 9, 'bold'))
        self.results_text.tag_configure('port', foreground='#cccccc', font=('Consolas', 9, 'bold'))
    
    def categorize_vulnerability_severity(self, vulnerability_text: str) -> str:
        """Categorize vulnerability severity based on text content."""
        vuln_lower = vulnerability_text.lower()
        
        # Critical vulnerabilities
        critical_keywords = [
            'critical', 'rce', 'remote code execution', 'backdoor', 'eternalblue', 
            'bluekeep', 'log4shell', 'heartbleed', 'spring4shell', 'shellshock',
            'ghost', 'krack', 'spectre', 'meltdown', 'zerologon'
        ]
        
        # High severity vulnerabilities
        high_keywords = [
            'high', 'buffer overflow', 'privilege escalation', 'authentication bypass',
            'sql injection', 'xss', 'csrf', 'directory traversal', 'path traversal',
            'denial of service', 'dos', 'use-after-free', 'heap overflow'
        ]
        
        # Medium severity vulnerabilities
        medium_keywords = [
            'medium', 'information disclosure', 'memory disclosure', 'session hijacking',
            'mitm', 'man-in-the-middle', 'weak cipher', 'ssl', 'tls', 'certificate'
        ]
        
        # Low severity vulnerabilities
        low_keywords = [
            'low', 'enumeration', 'fingerprinting', 'version disclosure',
            'configuration', 'header missing', 'clickjacking'
        ]
        
        # Check for critical vulnerabilities first
        for keyword in critical_keywords:
            if keyword in vuln_lower:
                return 'critical'
        
        # Check for high severity
        for keyword in high_keywords:
            if keyword in vuln_lower:
                return 'high'
        
        # Check for medium severity
        for keyword in medium_keywords:
            if keyword in vuln_lower:
                return 'medium'
        
        # Check for low severity
        for keyword in low_keywords:
            if keyword in vuln_lower:
                return 'low'
        
        # Default to info if no specific severity found
        return 'info'
    
    def get_severity_icon(self, severity: str) -> str:
        """Get the appropriate icon for vulnerability severity."""
        icons = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢',
            'info': '⚪'
        }
        return icons.get(severity, '⚪')
    
    def insert_colored_text(self, text: str, tag: str):
        """Insert text with specified color tag."""
        start_pos = self.results_text.index(tk.INSERT)
        self.results_text.insert(tk.END, text)
        end_pos = self.results_text.index(tk.INSERT)
        self.results_text.tag_add(tag, start_pos, end_pos)
    
    def start_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror('Error', 'Please enter a target IP address or range')
            return
        
        if self.is_scanning:
            messagebox.showwarning('Warning', 'Scan already in progress')
            return
        
        self.scan_results = []
        self.host_results = []
        self.results_text.delete('1.0', tk.END)
        
        self.is_scanning = True
        self.start_button.configure(state='disabled')
        self.stop_button.configure(state='normal')
        self.progress_var.set(0)
        self.progress_label.configure(text='0%')
        self.status_label.configure(text='Initializing scan...')
        
        self.scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        self.scan_thread.start()
    
    def stop_scan(self):
        if self.scanner:
            self.scanner.cancel_scan()
            self.log_message(' Scan cancellation requested...')
            self.status_label.configure(text='Stopping scan...')
    
    def run_scan(self):
        try:
            # Reset scanner state for new scan
            self.scanner.reset_scan()
            target = self.target_entry.get().strip()
            scan_type = self.scan_type_var.get()
            
            self.log_message(f' Starting {scan_type} scan on {target}')
            
            targets = self.scanner.validate_ip_input(target)
            self.log_message(f'🎯 Validated {len(targets)} targets')
            self.total_targets = len(targets)
            self.completed_targets = 0
            
            if scan_type == 'host_discovery':
                self.host_results = self.scanner.discover_hosts_detailed(targets, self.update_discovery_progress)
                if not self.scanner.interrupted:
                    self.log_message(f'✅ Host discovery complete: {len(self.host_results)} active hosts')
                    self.set_progress(100)
                    self.status_label.configure(text=f'Discovery complete: {len(self.host_results)} hosts found')
                    
            elif scan_type == 'single_host':
                self.set_progress(10)
                self.log_message('🔍 Starting port scan...')
                self.scan_results = self.scanner.perform_port_scan([target], progress_callback=self.update_port_progress)
                if not self.scanner.interrupted and self.scan_results:
                    self.set_progress(70)
                    self.log_message('🔍 Performing service detection...')
                    self.scan_results = self.scanner.detect_services(self.scan_results)
                    self.set_progress(85)
                    self.log_message('🔒 Assessing vulnerabilities...')
                    self.scan_results = self.scanner.assess_vulnerabilities(self.scan_results)
                    self.set_progress(100)
                    self.log_message(f'✅ Single host scan complete: {len(self.scan_results)} open ports')
                    
            else:  # network_quick
                self.set_progress(5)
                self.log_message('🔍 Discovering active hosts...')
                active_hosts = self.scanner.discover_hosts(targets)
                if not active_hosts or self.scanner.interrupted:
                    self.log_message('❌ No active hosts found or scan cancelled')
                    return
                    
                self.set_progress(25)
                self.log_message(f'🎯 Found {len(active_hosts)} active hosts')
                self.log_message('🚀 Starting port scan...')
                self.scan_results = self.scanner.perform_port_scan(active_hosts, progress_callback=self.update_port_progress)
                
                if not self.scanner.interrupted and self.scan_results:
                    self.set_progress(80)
                    self.log_message('🔍 Performing service detection...')
                    self.scan_results = self.scanner.detect_services(self.scan_results)
                    self.set_progress(90)
                    self.log_message('🔒 Assessing vulnerabilities...')
                    self.scan_results = self.scanner.assess_vulnerabilities(self.scan_results)
                    self.set_progress(100)
                    self.log_message(f'✅ Network scan complete: {len(self.scan_results)} open ports')
            
            self.refresh_results()
            
        except Exception as e:
            self.log_message(f'❌ Scan error: {e}')
        finally:
            self.scan_complete()
    
    def set_progress(self, percentage):
        """Set progress bar percentage."""
        self.progress_var.set(percentage)
        self.progress_label.configure(text=f'{int(percentage)}%')
        self.root.update_idletasks()
    
    def update_discovery_progress(self, message):
        """Update progress during host discovery."""
        self.log_message(message)
        if "Progress:" in message:
            # Extract progress from message like "Progress: 50/100 hosts processed"
            try:
                parts = message.split("Progress: ")[1].split("/")
                completed = int(parts[0])
                total = int(parts[1].split()[0])
                progress = int((completed / total) * 90)  # Discovery is 0-90%
                self.set_progress(progress)
            except:
                pass
    
    def update_port_progress(self, message):
        """Update progress during port scanning."""
        self.log_message(message)
        if "Progress:" in message:
            # Extract progress from port scan messages
            try:
                if "scans completed" in message:
                    parts = message.split("Progress: ")[1].split("/")
                    completed = int(parts[0])
                    total = int(parts[1].split()[0])
                    # Port scanning is 25-70% for network, 10-70% for single host
                    current = self.progress_var.get()
                    if current < 25:  # Single host mode
                        progress = 10 + int((completed / total) * 60)
                    else:  # Network mode
                        progress = 25 + int((completed / total) * 45)
                    self.set_progress(progress)
            except:
                pass
        elif "Open port found:" in message:
            # Small increment for each open port found
            current = self.progress_var.get()
            if current < 70:
                self.set_progress(current + 0.5)
    
    def scan_complete(self):
        self.is_scanning = False
        self.start_button.configure(state='normal')
        self.stop_button.configure(state='disabled')
        
        if self.scanner and not self.scanner.interrupted:
            self.log_message('🎉 Scan completed successfully!')
        else:
            self.log_message('⚠️ Scan was cancelled')
            self.status_label.configure(text='Scan cancelled')
            self.set_progress(0)
    
    def refresh_results(self):
        """Refresh results display with color-coded vulnerabilities."""
        self.results_text.delete('1.0', tk.END)
        
        if self.host_results:
            self.insert_colored_text('HOST DISCOVERY RESULTS\n', 'header')
            self.insert_colored_text('=' * 60 + '\n\n', 'header')
            
            for host_info in self.host_results:
                self.insert_colored_text(f'🖥️ Host: {host_info.ip}\n', 'host')
                self.results_text.insert(tk.END, f'    Hostname: {host_info.hostname}\n')
                self.results_text.insert(tk.END, f'    MAC: {host_info.mac_address}\n')
                self.results_text.insert(tk.END, f'    Vendor: {host_info.vendor}\n')
                self.results_text.insert(tk.END, f'    OS: {host_info.os_guess}\n')
                self.results_text.insert(tk.END, f'    Response: {int(host_info.response_time)}ms\n\n')
        
        if self.scan_results:
            self.insert_colored_text('PORT SCAN RESULTS\n', 'header')
            self.insert_colored_text('=' * 60 + '\n\n', 'header')
            
            hosts_data = {}
            for result in self.scan_results:
                if result.host not in hosts_data:
                    hosts_data[result.host] = []
                hosts_data[result.host].append(result)
            
            for host, results in hosts_data.items():
                self.insert_colored_text(f'🖥️ Host: {host}\n', 'host')
                self.results_text.insert(tk.END, '-' * 40 + '\n')
                
                for result in results:
                    self.insert_colored_text(f'   🔌 Port {result.port}: {result.service}\n', 'port')
                    if result.banner:
                        self.results_text.insert(tk.END, f'      📋 Banner: {result.banner}\n')
                    
                    if result.vulnerabilities:
                        self.results_text.insert(tk.END, f'      ⚠️ Vulnerabilities ({len(result.vulnerabilities)}):\n')
                        for vuln in result.vulnerabilities:
                            severity = self.categorize_vulnerability_severity(vuln)
                            severity_icon = self.get_severity_icon(severity)
                            self.insert_colored_text(f'         {severity_icon} {vuln}\n', severity)
                    else:
                        self.insert_colored_text('      ✅ No known vulnerabilities\n', 'secure')
                    
                    self.results_text.insert(tk.END, '\n')
                
                self.results_text.insert(tk.END, '-' * 40 + '\n\n')
        
        if not self.host_results and not self.scan_results:
            self.results_text.insert(tk.END, 'No scan results available. Run a scan first.')
    
    def export_json(self):
        filename = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON files', '*.json'), ('All files', '*.*')])
        
        if filename:
            try:
                data = {
                    'scan_timestamp': datetime.now().isoformat(),
                    'host_results': [{'ip': host.ip, 'hostname': host.hostname, 'mac_address': host.mac_address, 'vendor': host.vendor, 'os_guess': host.os_guess, 'response_time': host.response_time} for host in self.host_results],
                    'scan_results': [{'host': result.host, 'port': result.port, 'service': result.service, 'banner': result.banner, 'vulnerabilities': result.vulnerabilities} for result in self.scan_results]
                }
                
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
                
                messagebox.showinfo('Export', f'Results exported to {filename}')
                
            except Exception as e:
                messagebox.showerror('Error', f'Failed to export: {e}')
    
    def export_txt(self):
        filename = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Text files', '*.txt'), ('All files', '*.*')])
        
        if filename:
            try:
                content = self.results_text.get('1.0', tk.END)
                with open(filename, 'w') as f:
                    f.write(content)
                messagebox.showinfo('Export', f'Results exported to {filename}')
            except Exception as e:
                messagebox.showerror('Error', f'Failed to export: {e}')
    
    def log_message(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_entry = f'[{timestamp}] {message}\n'
        self.results_text.insert(tk.END, log_entry)
        self.results_text.see(tk.END)
    
    def run(self):
        self.root.mainloop()

def main():
    print(' Starting Network Scanner GUI...')
    app = NetworkScannerGUI()
    app.run()

if __name__ == '__main__':
    main()
