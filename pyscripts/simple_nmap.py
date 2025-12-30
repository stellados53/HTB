#!/usr/bin/env python3

import subprocess
import sys
import os
import re
import argparse
from pathlib import Path
import ipaddress

def run_command(cmd):
    """Execute a shell command and return the output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result
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

def extract_live_hosts(nmap_output):
    """Extract live hosts from nmap ping scan output"""
    live_hosts = []
    lines = nmap_output.split('\n')
    
    for line in lines:
        # Match lines like "Nmap scan report for 10.10.10.10"
        if "Nmap scan report for" in line:
            # Extract IP address
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                live_hosts.append(match.group(1))
    
    return live_hosts

def create_output_directory(dir_name="nmap_scans"):
    """Create output directory if it doesn't exist"""
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)
    return dir_name

def perform_host_discovery(target):
    """Perform host discovery to find live hosts"""
    print(f"\n[+] Performing host discovery for: {target}")
    
    # Use nmap -sn for ping scan (no port scan)
    discovery_cmd = f"nmap -sn {target}"
    print(f"Command: {discovery_cmd}")
    
    result = run_command(discovery_cmd)
    if result is None or result.returncode != 0:
        print(f"[-] Host discovery failed for {target}")
        return []
    
    live_hosts = extract_live_hosts(result.stdout)
    
    if live_hosts:
        print(f"[+] Found {len(live_hosts)} live host(s):")
        for host in live_hosts:
            print(f"    - {host}")
    else:
        print(f"[-] No live hosts found for {target}")
    
    return live_hosts

def scan_single_ip(ip, output_dir=None):
    """Perform complete nmap scan for a single IP"""
    print(f"\n{'='*60}")
    print(f"Scanning target: {ip}")
    print(f"{'='*60}")
    
    # Step 0: Check if host is alive (quick ping check)
    print(f"[+] Checking if host is alive...")
    ping_cmd = f"ping -c 2 -W 2 {ip} > /dev/null 2>&1 && echo 'alive' || echo 'dead'"
    ping_result = run_command(ping_cmd)
    
    if ping_result and 'alive' not in ping_result.stdout:
        print(f"[-] Host {ip} appears to be down. Skipping detailed scan.")
        print(f"[-] You can force scan with --no-ping-check option")
        
        # Still create a minimal report file if output_dir is specified
        if output_dir:
            output_path = os.path.join(output_dir, f"{ip}.nmap")
            with open(output_path, 'w') as f:
                f.write(f"Host {ip} appears to be down (no response to ping)\n")
                f.write(f"Scan skipped at {run_command('date').stdout.strip()}\n")
        
        return False
    
    # Step 1: Port discovery scan
    print(f"\n[+] Initiating port discovery scan for {ip}")
    port_scan_cmd = f"sudo nmap -p- --min-rate=10000 {ip}"
    print(f"Command: {port_scan_cmd}")
    
    result = run_command(port_scan_cmd)
    if result is None or result.returncode != 0:
        print(f"[-] Failed to run port discovery scan for {ip}")
        return False
    
    port_scan_output = result.stdout
    
    # Extract open ports
    open_ports = extract_open_ports(port_scan_output)
    
    if not open_ports:
        print(f"[-] No open ports found for {ip}")
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
    
    result = run_command(script_scan_cmd)
    if result is None or result.returncode != 0:
        print(f"[-] Failed to run script scan for {ip}")
        return False
    
    script_scan_output = result.stdout
    
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

def scan_multiple_targets(targets, no_ping_check=False):
    """Scan multiple targets with host discovery first"""
    # Create output directory
    output_dir = create_output_directory()
    print(f"\n[+] Created output directory: {output_dir}")
    
    all_live_hosts = []
    
    # First, discover live hosts from all targets
    for target in targets:
        if no_ping_check:
            # If no ping check, treat all targets as live
            print(f"[!] Skipping host discovery for {target} (--no-ping-check)")
            # For ranges/CIDR, we need to expand them
            if '/' in target or '-' in target:
                # Use nmap to list hosts without scanning
                list_cmd = f"nmap -sL {target} | grep 'Nmap scan report' | cut -d' ' -f5"
                result = run_command(list_cmd)
                if result and result.stdout:
                    expanded_hosts = [ip.strip() for ip in result.stdout.split('\n') if ip.strip()]
                    all_live_hosts.extend(expanded_hosts)
                    print(f"[+] Expanded {target} to {len(expanded_hosts)} hosts")
            else:
                all_live_hosts.append(target)
        else:
            live_hosts = perform_host_discovery(target)
            all_live_hosts.extend(live_hosts)
    
    # Remove duplicates
    all_live_hosts = list(set(all_live_hosts))
    
    if not all_live_hosts:
        print(f"\n[-] No live hosts found. Exiting.")
        return False
    
    print(f"\n[+] Found {len(all_live_hosts)} unique live host(s) to scan")
    print(f"[+] Starting detailed scans...")
    
    successful_scans = 0
    for host in all_live_hosts:
        print(f"\n{'#'*60}")
        print(f"Scanning live host: {host}")
        print(f"{'#'*60}")
        
        if scan_single_ip(host, output_dir):
            successful_scans += 1
    
    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"Successfully scanned: {successful_scans}/{len(all_live_hosts)} live hosts")
    print(f"Output directory: {output_dir}")
    
    # Create a summary file
    summary_path = os.path.join(output_dir, "scan_summary.txt")
    with open(summary_path, 'w') as f:
        f.write(f"Nmap Scan Summary\n")
        f.write(f"=================\n\n")
        f.write(f"Total targets provided: {len(targets)}\n")
        f.write(f"Live hosts found: {len(all_live_hosts)}\n")
        f.write(f"Successfully scanned: {successful_scans}\n")
        f.write(f"Scan date: {run_command('date').stdout.strip()}\n\n")
        f.write("Live hosts scanned:\n")
        for host in sorted(all_live_hosts):
            f.write(f"  - {host}\n")
    
    print(f"[+] Summary saved to: {summary_path}")
    
    return successful_scans > 0

def scan_from_file(filename, no_ping_check=False):
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
        return scan_multiple_targets(targets, no_ping_check)
        
    except FileNotFoundError:
        print(f"[-] File {filename} not found")
        return False
    except Exception as e:
        print(f"[-] Error reading file {filename}: {e}")
        return False

def validate_target(target):
    """Validate if target looks like a valid nmap target"""
    # Check for CIDR notation
    if '/' in target:
        parts = target.split('/')
        if len(parts) == 2:
            try:
                # Try to parse as IP network
                ipaddress.ip_network(target, strict=False)
                return True
            except ValueError:
                return False
    
    # Check for IP range (e.g., 10.10.10.10-20)
    if '-' in target and not target.startswith('-'):
        # Remove any whitespace
        target = target.replace(' ', '')
        range_parts = target.split('-')
        if len(range_parts) == 2:
            base_ip = range_parts[0]
            # Check if base IP is valid
            try:
                ipaddress.ip_address(base_ip)
                return True
            except ValueError:
                return False
    
    # Check for single IP or hostname
    try:
        # Try as IP address
        ipaddress.ip_address(target)
        return True
    except ValueError:
        # Try as hostname (basic check)
        hostname_pattern = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\.\-]*[a-zA-Z0-9]$')
        return hostname_pattern.match(target) is not None

def show_manual():
    """Display the manual/help page"""
    manual = """
NMAP SCANNER - Automated Nmap Scanning Tool
============================================

DESCRIPTION:
This script automates the two-phase Nmap scanning process with host discovery:
1. First, performs host discovery to find live hosts
2. Then, performs comprehensive port discovery scan on live hosts
3. Finally, runs detailed script and version scans on discovered ports

FEATURES:
- Host discovery before scanning (saves time on dead hosts)
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
    -h, --help          Show this help message and exit
    --version           Show version information
    --no-ping-check     Skip host discovery and scan all targets

EXAMPLES:
    1. Scan single target with host check:
       python3 nmap_scanner.py 192.168.1.100

    2. Scan CIDR range with host discovery:
       python3 nmap_scanner.py 10.10.10.0/24

    3. Scan IP range without host discovery:
       python3 nmap_scanner.py 10.10.10.10-20 --no-ping-check

    4. Scan targets from file:
       python3 nmap_scanner.py target_list.txt

OUTPUT:
    Single target:      <IP>.nmap in current directory
    Multiple targets:   All files in nmap_scans/ directory
                        + scan_summary.txt with results

HOST DISCOVERY:
    By default, the script performs host discovery first using nmap -sn.
    This prevents wasting time scanning dead hosts.
    Use --no-ping-check to disable this behavior.
    """
    print(manual)

def show_version():
    """Display version information"""
    version_info = """
Nmap Scanner v2.1
Automated Nmap Scanning Tool with Host Discovery
Created for comprehensive network reconnaissance
"""
    print(version_info)

def main():
    parser = argparse.ArgumentParser(description='Automated Nmap Scanner', add_help=False)
    parser.add_argument('targets', nargs='*', help='Target(s) to scan (IPs, ranges, hostnames, or file)')
    parser.add_argument('-h', '--help', action='store_true', help='Show help message')
    parser.add_argument('--version', action='store_true', help='Show version information')
    parser.add_argument('--no-ping-check', action='store_true', help='Skip host discovery and scan all targets')
    
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
            # Scan from file
            scan_from_file(all_targets[0], args.no_ping_check)
        else:
            # Single target scan
            target = all_targets[0]
            if validate_target(target):
                if not args.no_ping_check:
                    # Still do a quick ping check for single IP
                    scan_single_ip(target)
                else:
                    # Skip ping check
                    scan_single_ip(target)
            else:
                print(f"[-] Invalid target format: {target}")
                print("[!] Valid formats: IP, IP range, CIDR, or hostname")
    else:
        # Multiple targets
        valid_targets = []
        for target in all_targets:
            if validate_target(target):
                valid_targets.append(target)
            else:
                print(f"[-] Invalid target format: {target}")
        
        if valid_targets:
            scan_multiple_targets(valid_targets, args.no_ping_check)
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
