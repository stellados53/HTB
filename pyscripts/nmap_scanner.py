#!/usr/bin/env python3

import subprocess
import sys
import os
import re
import argparse
from pathlib import Path
import shutil

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

def create_output_directory(dir_name="nmap_scans"):
    """Create output directory if it doesn't exist"""
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)
    return dir_name

def scan_single_ip(ip, output_dir=None):
    """Perform complete nmap scan for a single IP"""
    print(f"\n{'='*60}")
    print(f"Scanning target: {ip}")
    print(f"{'='*60}")
    
    # Step 1: Port discovery scan
    print(f"\n[+] Initiating port discovery scan for {ip}")
    port_scan_cmd = f"sudo nmap -p- --min-rate=10000 {ip}"
    print(f"Command: {port_scan_cmd}")
    
    port_scan_output = run_command(port_scan_cmd)
    if port_scan_output is None:
        print(f"[-] Failed to run port discovery scan for {ip}")
        return False
    
    # Extract open ports
    open_ports = extract_open_ports(port_scan_output)
    
    if not open_ports:
        print(f"[-] No open ports found for {ip}")
        # Still save the scan results even if no ports are open
        ports_string = ""
    else:
        ports_string = ','.join(open_ports)
        print(f"\n[+] Found open ports: {ports_string}")
    
    # Step 2: Script and version scan
    print(f"\n[+] Initiating script and version scan for {ip}")
    if ports_string:
        script_scan_cmd = f"sudo nmap -sC -sV -O {ip} -p {ports_string}"
    else:
        script_scan_cmd = f"sudo nmap -sC -sV -O {ip}"
    
    print(f"Command: {script_scan_cmd}")
    
    script_scan_output = run_command(script_scan_cmd)
    if script_scan_output is None:
        print(f"[-] Failed to run script scan for {ip}")
        return False
    
    # Combine both outputs
    combined_output = f"{'='*60}\n"
    combined_output += f"COMPLETE NMAP SCAN REPORT FOR {ip}\n"
    combined_output += f"{'='*60}\n\n"
    
    combined_output += "PORT DISCOVERY SCAN RESULTS:\n"
    combined_output += "-" * 40 + "\n"
    combined_output += port_scan_output
    combined_output += "\n\n"
    
    combined_output += "SCRIPT AND VERSION SCAN RESULTS:\n"
    combined_output += "-" * 40 + "\n"
    combined_output += script_scan_output
    
    # Save the output
    if output_dir:
        # For multiple IPs, save in directory
        output_path = os.path.join(output_dir, f"{ip}.nmap")
    else:
        # For single IP, save in current directory with .nmap extension
        output_path = f"{ip}.nmap"
    
    with open(output_path, 'w') as f:
        f.write(combined_output)
    
    print(f"[+] Scan results saved to: {output_path}")
    
    # Also print summary to console
    print(f"\n[+] Scan Summary for {ip}:")
    print("-" * 40)
    if ports_string:
        print(f"Open ports: {ports_string}")
        print(f"Total open ports: {len(open_ports)}")
    else:
        print("No open ports found")
    print(f"Full report: {output_path}")
    
    return True

def scan_multiple_targets(targets):
    """Scan multiple targets (IPs, ranges, or from file)"""
    # Create output directory
    output_dir = create_output_directory()
    print(f"\n[+] Created output directory: {output_dir}")
    print(f"[+] Scanning {len(targets)} target(s)...")
    
    successful_scans = 0
    for target in targets:
        # For targets that might be ranges (like 10.10.10.10-20),
        # we need to expand them first. However, nmap handles ranges natively.
        # We'll pass the target directly and let nmap handle it.
        print(f"\n{'#'*60}")
        print(f"Processing target: {target}")
        print(f"{'#'*60}")
        
        if scan_target(target, output_dir):
            successful_scans += 1
    
    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"Successfully scanned: {successful_scans}/{len(targets)} targets")
    print(f"Output directory: {output_dir}")
    
    return successful_scans > 0

def scan_target(target, output_dir):
    """Scan a single target (could be IP, hostname, or range)"""
    print(f"\n[+] Scanning target: {target}")
    
    # Step 1: Port discovery scan
    print(f"[+] Initiating port discovery scan...")
    port_scan_cmd = f"sudo nmap -p- --min-rate=10000 {target}"
    port_scan_output = run_command(port_scan_cmd)
    
    if port_scan_output is None:
        print(f"[-] Failed to run port discovery scan for {target}")
        return False
    
    # Extract open ports from the output
    open_ports = extract_open_ports(port_scan_output)
    
    if open_ports:
        ports_string = ','.join(open_ports)
        print(f"[+] Found {len(open_ports)} open port(s)")
    else:
        ports_string = ""
        print(f"[!] No open ports found")
    
    # Step 2: Script and version scan
    print(f"[+] Initiating script and version scan...")
    if ports_string:
        script_scan_cmd = f"sudo nmap -sC -sV -O {target} -p {ports_string}"
    else:
        script_scan_cmd = f"sudo nmap -sC -sV -O {target}"
    
    script_scan_output = run_command(script_scan_cmd)
    if script_scan_output is None:
        print(f"[-] Failed to run script scan for {target}")
        return False
    
    # Combine outputs
    combined_output = f"{'='*60}\n"
    combined_output += f"COMPLETE NMAP SCAN REPORT FOR: {target}\n"
    combined_output += f"{'='*60}\n\n"
    
    combined_output += "PORT DISCOVERY SCAN RESULTS:\n"
    combined_output += "-" * 40 + "\n"
    combined_output += port_scan_output
    combined_output += "\n\n"
    
    combined_output += "SCRIPT AND VERSION SCAN RESULTS:\n"
    combined_output += "-" * 40 + "\n"
    combined_output += script_scan_output
    
    # Save output with sanitized filename
    # Replace characters that might cause issues in filenames
    safe_filename = re.sub(r'[^\w\.\-]', '_', target)
    output_path = os.path.join(output_dir, f"{safe_filename}.nmap")
    
    with open(output_path, 'w') as f:
        f.write(combined_output)
    
    print(f"[✓] Scan saved to: {output_path}")
    return True

def scan_from_file(filename):
    """Scan targets from a file"""
    try:
        with open(filename, 'r') as f:
            # Read all non-empty, non-comment lines
            targets = []
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
        
        if not targets:
            print(f"[-] No valid targets found in {filename}")
            return False
        
        print(f"[+] Loaded {len(targets)} target(s) from {filename}")
        return scan_multiple_targets(targets)
        
    except FileNotFoundError:
        print(f"[-] File {filename} not found")
        return False
    except Exception as e:
        print(f"[-] Error reading file {filename}: {e}")
        return False

def validate_target(target):
    """Validate if target looks like a valid nmap target"""
    # Basic validation for IP, hostname, or range
    # This is permissive to allow nmap to handle validation
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|-\d{1,3})?$')
    hostname_pattern = re.compile(r'^[a-zA-Z0-9\.\-]+$')
    
    if ip_pattern.match(target) or hostname_pattern.match(target):
        return True
    
    # Check for CIDR notation
    if '/' in target:
        parts = target.split('/')
        if len(parts) == 2 and ip_pattern.match(parts[0]):
            try:
                mask = int(parts[1])
                return 0 <= mask <= 32
            except ValueError:
                return False
    
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
- Support for single IP, multiple IPs, IP ranges, and files

USAGE:
    python3 nmap_scanner.py [TARGET] [OPTIONS]

TARGET FORMATS:
    Single IP:          python3 nmap_scanner.py 10.10.10.10
    Multiple IPs:       python3 nmap_scanner.py 10.10.10.11 10.10.10.12
    IP Range:           python3 nmap_scanner.py 10.10.10.10-20
    CIDR Notation:      python3 nmap_scanner.py 10.10.10.0/24
    From File:          python3 nmap_scanner.py targets.txt
    Hostname:           python3 nmap_scanner.py example.com

OPTIONS:
    -h, --help      Show this help message and exit
    --version       Show version information

EXAMPLES:
    1. Scan single target (saved as 192.168.1.100.nmap):
       python3 nmap_scanner.py 192.168.1.100

    2. Scan multiple targets (saved in nmap_scans/ directory):
       python3 nmap_scanner.py 192.168.1.100 192.168.1.101

    3. Scan IP range (saved in nmap_scans/ directory):
       python3 nmap_scanner.py 10.10.10.10-20

    4. Scan targets from file (saved in nmap_scans/ directory):
       python3 nmap_scanner.py target_list.txt

    5. Show this help:
       python3 nmap_scanner.py

OUTPUT:
    Single target:      <IP>.nmap in current directory
    Multiple targets:   All files in nmap_scans/ directory

REQUIREMENTS:
    - Nmap must be installed and accessible in PATH
    - Script requires sudo privileges for certain Nmap options
    - Python 3.6 or higher

NOTES:
    - The script uses aggressive timing (--min-rate=10000) for faster scans
    - OS detection requires root privileges
    """
    print(manual)

def show_version():
    """Display version information"""
    version_info = """
Nmap Scanner v2.0
Automated Two-Phase Nmap Scanning Tool
Created for comprehensive network reconnaissance
"""
    print(version_info)

def main():
    parser = argparse.ArgumentParser(description='Automated Nmap Scanner', add_help=False)
    parser.add_argument('targets', nargs='*', help='Target(s) to scan (IPs, ranges, hostnames, or file)')
    parser.add_argument('-h', '--help', action='store_true', help='Show help message')
    parser.add_argument('--version', action='store_true', help='Show version information')
    
    args, unknown = parser.parse_known_args()
    
    if args.help or (not args.targets and not unknown):
        show_manual()
        return
    
    if args.version:
        show_version()
        return
    
    # Combine known targets with unknown args
    all_targets = args.targets + unknown
    
    if not all_targets:
        show_manual()
        return
    
    # Check if single target (not a file)
    if len(all_targets) == 1:
        # Check if it's a file
        if os.path.isfile(all_targets[0]):
            # Scan from file (multiple targets)
            scan_from_file(all_targets[0])
        else:
            # Single target scan
            target = all_targets[0]
            if validate_target(target):
                scan_single_ip(target)
            else:
                print(f"[-] Invalid target format: {target}")
                print("[!] Valid formats: IP, IP range, CIDR, or hostname")
    else:
        # Multiple targets
        # Validate all targets
        valid_targets = []
        for target in all_targets:
            if validate_target(target):
                valid_targets.append(target)
            else:
                print(f"[-] Invalid target format: {target}")
        
        if valid_targets:
            scan_multiple_targets(valid_targets)
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
        print("[!] Some scans may require root privileges.")
        print("[!] Continuing anyway...")
    
    main()
