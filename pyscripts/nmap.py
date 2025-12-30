#!/usr/bin/env python3

import subprocess
import sys
import os
import argparse
from datetime import datetime

def run_cmd(cmd, show_cmd=True):
    """Run command with real-time output"""
    if show_cmd:
        print(f"\n\033[94m[+] {cmd}\033[0m")
    
    process = subprocess.Popen(
        cmd, 
        shell=True, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.STDOUT, 
        text=True
    )
    
    for line in iter(process.stdout.readline, ''):
        print(line, end='')
    
    process.stdout.close()
    return process.wait() == 0

def main():
    parser = argparse.ArgumentParser(description='Simple Nmap Scanner')
    parser.add_argument('targets', nargs='*', help='Targets to scan (IPs, ranges, CIDR)')
    parser.add_argument('-iL', '--input-file', help='File with targets')
    parser.add_argument('--no-ping', action='store_true', help='Skip host discovery')
    
    args = parser.parse_args()
    
    # Get targets
    targets = []
    if args.input_file and os.path.exists(args.input_file):
        with open(args.input_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    elif args.targets:
        targets = args.targets
    else:
        parser.print_help()
        return
    
    if not targets:
        print("\033[91m[-] No targets specified\033[0m")
        return
    
    # Create scan directory with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_dir = f"scans_{timestamp}"
    os.makedirs(scan_dir, exist_ok=True)
    print(f"\033[92m[+] Scan directory: {scan_dir}/\033[0m")
    
    # Save all targets to file
    targets_file = os.path.join(scan_dir, "all_targets.txt")
    with open(targets_file, 'w') as f:
        f.write('\n'.join(targets))
    print(f"\033[92m[+] Targets saved: {targets_file}\033[0m")
    
    # ========== STAGE 1: HOST DISCOVERY ==========
    print(f"\n\033[95m{'='*60}")
    print("STAGE 1: HOST DISCOVERY")
    print(f"{'='*60}\033[0m")
    
    live_hosts_file = os.path.join(scan_dir, "live-hosts.txt")
    
    if args.no_ping:
        print("\033[93m[!] Skipping host discovery (--no-ping)\033[0m")
        # Copy all targets as live hosts
        with open(live_hosts_file, 'w') as f:
            f.write('\n'.join(targets))
        print(f"\033[92m[+] Assuming all {len(targets)} targets are live\033[0m")
    else:
        # Run nmap ping scan
        host_discovery_nmap = os.path.join(scan_dir, "host_discovery.nmap")
        cmd = f"nmap -sn -iL {targets_file} -oN {host_discovery_nmap}"
        run_cmd(cmd)
        
        # Extract live hosts
        cmd = f"grep 'Nmap scan report' {host_discovery_nmap} | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' > {live_hosts_file}"
        if run_cmd(cmd, show_cmd=False):
            # Count live hosts
            cmd = f"wc -l {live_hosts_file}"
            run_cmd(cmd, show_cmd=False)
        else:
            print("\033[91m[-] No live hosts found\033[0m")
            return
    
    # Read live hosts
    with open(live_hosts_file, 'r') as f:
        live_hosts = [line.strip() for line in f if line.strip()]
    
    if not live_hosts:
        print("\033[91m[-] No live hosts to scan\033[0m")
        return
    
    print(f"\033[92m[+] Found {len(live_hosts)} live hosts\033[0m")
    
    # ========== STAGE 2: DETAILED SCANNING ==========
    print(f"\n\033[95m{'='*60}")
    print("STAGE 2: PORT & SERVICE SCANNING")
    print(f"{'='*60}\033[0m")
    
    # Create detailed scans directory
    # detailed_dir = os.path.join(scan_dir, "detailed_scans")
    # os.makedirs(detailed_dir, exist_ok=True)
    
    # Scan each live host
    for i, host in enumerate(live_hosts, 1):
        print(f"\n\033[96m[ {i}/{len(live_hosts)} ] Scanning: {host}")
        print(f"{'-'*50}\033[0m")
        
        # Create host directory
        host_dir = os.path.join(scan_dir, host)
        os.makedirs(host_dir, exist_ok=True)
        
        # Phase 1: Full port scan
        print(f"\033[94m[1] Finding all open ports...\033[0m")
        port_scan_base = os.path.join(host_dir, "port_scan")
        cmd = f"sudo nmap -p- --min-rate=10000 {host} -oA {port_scan_base}"
        run_cmd(cmd)
        
        # Extract open ports from nmap output
        cmd = f"grep '/tcp.*open' {port_scan_base}.nmap | cut -d'/' -f1 | tr '\\n' ',' | sed 's/,$//'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        ports = result.stdout.strip()
        
        if not ports:
            print(f"\033[93m[!] No open ports for {host}\033[0m")
            continue
        
        print(f"\033[92m[+] Open ports: {ports}\033[0m")
        
        # Phase 2: Script and version scan
        print(f"\033[94m[2] Running script & version scan...\033[0m")
        script_scan_base = os.path.join(host_dir, "script_scan")
        cmd = f"sudo nmap -sC -sV -O -p {ports} {host} -oA {script_scan_base}"
        run_cmd(cmd)
        
        print(f"\033[92m[✓] Completed scan for {host}\033[0m")
        print(f"\033[92m[+] Files saved in: {host_dir}/\033[0m")
    
    # ========== FINAL SUMMARY ==========
    print(f"\n\033[95m{'='*60}")
    print("SCAN COMPLETE")
    print(f"{'='*60}\033[0m")
    
    print(f"\n\033[92m[+] Total hosts scanned: {len(live_hosts)}\033[0m")
    print(f"\033[92m[+] All results saved in: {scan_dir}/\033[0m")
    
    print(f"\033[92m[+] Use individual XML files for EyeWitness if needed\033[0m")
    print(f"\033[92m[+] Example: eyewitness --web -x {scan_dir}/10.129.174.177/script_scan.xml\033[0m")

if __name__ == "__main__":
    # Check if nmap is installed
    if subprocess.run(["which", "nmap"], capture_output=True).returncode != 0:
        print("\033[91m[-] Nmap not found. Install with: sudo apt install nmap\033[0m")
        sys.exit(1)
    
    # Check if running with sudo (optional warning)
    if os.geteuid() != 0:
        print("\033[93m[!] Not running as root. Some features may need sudo.\033[0m")
    
    main()
