#!/usr/bin/env python3

import subprocess
import sys
import os
import re
import argparse
from pathlib import Path

def run_command(cmd):
    """Execute a shell command and return the output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error running command: {cmd}")
            print(f"Error: {result.stderr}")
            return None
        return result.stdout
    except Exception as e:
        print(f"Exception running command {cmd}: {e}")
        return None

def extract_open_ports(nmap_output):
    """Extract open ports from nmap output"""
    open_ports = []
    lines = nmap_output.split('\n')
    
    for line in lines:
        # Match port lines like "135/tcp  open  msrpc"
        match = re.match(r'^(\d+)/tcp\s+open\s+\S+', line.strip())
        if match:
            open_ports.append(match.group(1))
    
    return open_ports

def scan_single_ip(ip):
    """Perform complete nmap scan for a single IP"""
    print(f"\n{'='*60}")
    print(f"Scanning target: {ip}")
    print(f"{'='*60}")
    
    # Step 1: Port discovery scan
    print(f"\n[+] Initiating port discovery scan for {ip}")
    port_scan_cmd = f"sudo nmap -p- --min-rate=10000 {ip} -oN nmap_open_ports_{ip}.txt"
    print(f"Command: {port_scan_cmd}")
    
    port_scan_output = run_command(port_scan_cmd)
    if port_scan_output is None:
        print(f"[-] Failed to run port discovery scan for {ip}")
        return False
    
    # Read the saved port scan output
    try:
        with open(f"nmap_open_ports_{ip}.txt", 'r') as f:
            port_scan_output = f.read()
    except FileNotFoundError:
        print(f"[-] Port scan output file not found for {ip}")
        return False
    
    # Display port scan results
    print(f"\n[+] Port Scan Results for {ip}:")
    print("-" * 40)
    print(port_scan_output.split('Nmap scan report')[1].split('\n\n')[0] if 'Nmap scan report' in port_scan_output else port_scan_output)
    
    # Extract open ports
    open_ports = extract_open_ports(port_scan_output)
    
    if not open_ports:
        print(f"[-] No open ports found for {ip}")
        return True
    
    ports_string = ','.join(open_ports)
    print(f"\n[+] Found open ports: {ports_string}")
    
    # Step 2: Script and version scan
    print(f"\n[+] Initiating script and version scan for {ip}")
    script_scan_cmd = f"sudo nmap -sC -sV -O {ip} -p {ports_string} -oN nmap_scripts_{ip}.txt"
    print(f"Command: {script_scan_cmd}")
    
    script_scan_output = run_command(script_scan_cmd)
    if script_scan_output is None:
        print(f"[-] Failed to run script scan for {ip}")
        return False
    
    # Read the saved script scan output
    try:
        with open(f"nmap_scripts_{ip}.txt", 'r') as f:
            script_scan_output = f.read()
    except FileNotFoundError:
        print(f"[-] Script scan output file not found for {ip}")
        return False
    
    # Display script scan results
    print(f"\n[+] Script Scan Results for {ip}:")
    print("-" * 40)
    print(script_scan_output)
    
    # Step 3: Combine both outputs
    print(f"\n[+] Combining scan results for {ip}")
    combined_filename = f"nmap_full_scan_{ip}.txt"
    
    with open(combined_filename, 'w') as f:
        f.write("=" * 60 + "\n")
        f.write(f"COMPLETE NMAP SCAN REPORT FOR {ip}\n")
        f.write("=" * 60 + "\n\n")
        
        f.write("PORT DISCOVERY SCAN RESULTS:\n")
        f.write("-" * 40 + "\n")
        f.write(port_scan_output)
        f.write("\n\n")
        
        f.write("SCRIPT AND VERSION SCAN RESULTS:\n")
        f.write("-" * 40 + "\n")
        f.write(script_scan_output)
    
    print(f"[+] Combined results saved to: {combined_filename}")
    return True

def scan_multiple_ips(ip_list):
    """Scan multiple IP addresses"""
    print(f"\n[+] Scanning {len(ip_list)} targets...")
    
    for ip in ip_list:
        scan_single_ip(ip)

def scan_from_file(filename):
    """Scan IPs from a file"""
    try:
        with open(filename, 'r') as f:
            ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        if not ips:
            print(f"[-] No valid IPs found in {filename}")
            return
        
        print(f"[+] Loaded {len(ips)} targets from {filename}")
        scan_multiple_ips(ips)
        
    except FileNotFoundError:
        print(f"[-] File {filename} not found")
    except Exception as e:
        print(f"[-] Error reading file {filename}: {e}")

def validate_ip(ip):
    """Basic IP validation"""
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if ip_pattern.match(ip):
        octets = ip.split('.')
        for octet in octets:
            if not (0 <= int(octet) <= 255):
                return False
        return True
    return False

def show_manual():
    """Display the manual/help page"""
    manual = """
NMAP SCANNER - Automated Nmap Scanning Tool
============================================

DESCRIPTION:
This script automates the two-phase Nmap scanning process:
1. First, it performs a comprehensive port discovery scan
2. Then, it runs detailed script and version scans on discovered ports

FEATURES:
- Automatic port discovery using aggressive timing
- Script scanning (-sC) and version detection (-sV)
- OS detection (-O)
- Combined output files
- Support for single IP, multiple IPs, and IP list files

USAGE:
    python3 nmap_scanner.py [TARGET] [OPTIONS]

TARGET FORMATS:
    Single IP:      python3 nmap_scanner.py 10.10.10.10
    Multiple IPs:   python3 nmap_scanner.py 10.10.10.11 10.10.10.12
    IP File:        python3 nmap_scanner.py targets.txt

OPTIONS:
    -h, --help      Show this help message and exit
    --version       Show version information

EXAMPLES:
    1. Scan single target:
       python3 nmap_scanner.py 192.168.1.100

    2. Scan multiple targets:
       python3 nmap_scanner.py 192.168.1.100 192.168.1.101 192.168.1.102

    3. Scan targets from file:
       python3 nmap_scanner.py target_list.txt

    4. Show this help:
       python3 nmap_scanner.py

OUTPUT FILES:
    For each target IP, three files are created:
    - nmap_open_ports_<IP>.txt    : Initial port discovery results
    - nmap_scripts_<IP>.txt       : Script and version scan results  
    - nmap_full_scan_<IP>.txt     : Combined results

REQUIREMENTS:
    - Nmap must be installed and accessible in PATH
    - Script requires sudo privileges for certain Nmap options
    - Python 3.6 or higher

NOTES:
    - The script uses aggressive timing (--min-rate=10000) for faster scans
    - OS detection requires root privileges
    - Results are saved in the current working directory
    """
    print(manual)

def show_version():
    """Display version information"""
    version_info = """
Nmap Scanner v1.0
Automated Two-Phase Nmap Scanning Tool
Created for comprehensive network reconnaissance
"""
    print(version_info)

def main():
    parser = argparse.ArgumentParser(description='Automated Nmap Scanner', add_help=False)
    parser.add_argument('targets', nargs='*', help='IP addresses or file containing IPs')
    parser.add_argument('-h', '--help', action='store_true', help='Show help message')
    parser.add_argument('--version', action='store_true', help='Show version information')
    
    # Parse known args to handle help before processing targets
    args, unknown = parser.parse_known_args()
    
    if args.help or (not args.targets and not unknown):
        show_manual()
        return
    
    if args.version:
        show_version()
        return
    
    # Combine known targets with unknown args (for multiple IPs without --)
    all_targets = args.targets + unknown
    
    if not all_targets:
        show_manual()
        return
    
    # Check if first argument is a file
    if len(all_targets) == 1 and os.path.isfile(all_targets[0]):
        scan_from_file(all_targets[0])
    else:
        # Validate IPs
        valid_ips = []
        for target in all_targets:
            if validate_ip(target):
                valid_ips.append(target)
            else:
                print(f"[-] Invalid IP address: {target}")
        
        if valid_ips:
            if len(valid_ips) == 1:
                scan_single_ip(valid_ips[0])
            else:
                scan_multiple_ips(valid_ips)
        else:
            print("[-] No valid targets specified")
            show_manual()

if __name__ == "__main__":
    # Check if nmap is available
    if run_command("which nmap") is None:
        print("[-] Nmap is not installed or not in PATH")
        print("[-] Please install nmap before running this script")
        sys.exit(1)
    
    # Check if running with sudo for OS detection
    if os.geteuid() != 0:
        print("[!] Warning: Not running as root. OS detection may not work properly.")
        print("[!] Consider running with sudo for full functionality.")
    
    main()
