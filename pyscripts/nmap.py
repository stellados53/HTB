#!/usr/bin/env python3

import subprocess
import sys
import os
import re
import argparse
from datetime import datetime
import time

def run_command_real_time(cmd):
    """Execute command with real-time output"""
    print(f"\n\033[94m[+] Running: {cmd}\033[0m")
    try:
        # Run command with real-time output
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        # Print output in real-time
        for line in iter(process.stdout.readline, ''):
            print(line, end='')
        
        process.stdout.close()
        return_code = process.wait()
        
        if return_code != 0:
            print(f"\033[91m[-] Command failed with code: {return_code}\033[0m")
            return False
        return True
        
    except Exception as e:
        print(f"\033[91m[-] Exception: {e}\033[0m")
        return False

def get_unique_filename(base_name, extension):
    """Get unique filename if file already exists"""
    counter = 1
    while True:
        if counter == 1:
            filename = f"{base_name}.{extension}"
        else:
            filename = f"{base_name}-{counter}.{extension}"
        
        if not os.path.exists(filename):
            return filename
        counter += 1

def create_output_directory():
    """Create timestamped output directory"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"scans_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    print(f"\033[92m[+] Created output directory: {output_dir}\033[0m")
    return output_dir

def discover_live_hosts(targets, output_dir):
    """Use nmap -sn to discover live hosts"""
    print(f"\n\033[95m{'='*80}\033[0m")
    print(f"\033[95m[ STAGE 1: HOST DISCOVERY ]\033[0m")
    print(f"\033[95m{'='*80}\033[0m")
    
    # Save targets to file for nmap -iL
    targets_file = os.path.join(output_dir, "input_targets.txt")
    with open(targets_file, 'w') as f:
        if isinstance(targets, list):
            for target in targets:
                f.write(f"{target}\n")
        else:
            f.write(f"{targets}\n")
    
    # Base output files
    base_output = os.path.join(output_dir, "host_discovery")
    
    # Run nmap host discovery with real-time output
    cmd = f"nmap -sn -iL {targets_file} -oN {base_output}"
    success = run_command_real_time(cmd)
    
    if not success:
        return None, None
    
    # Create live hosts file
    live_hosts_file = get_unique_filename("live-hosts", "txt")
    live_hosts_path = os.path.join(output_dir, live_hosts_file)
    
    # Extract live hosts from XML output
    xml_file = f"{base_output}.xml"
    if os.path.exists(xml_file):
        live_hosts = extract_hosts_from_xml(xml_file)
        
        if live_hosts:
            with open(live_hosts_path, 'w') as f:
                for host in live_hosts:
                    f.write(f"{host}\n")
            
            print(f"\n\033[92m[+] Found {len(live_hosts)} live hosts\033[0m")
            print(f"\033[92m[+] Live hosts saved to: {live_hosts_path}\033[0m")
            print(f"\033[92m[+] EyeWitness XML file: {xml_file}\033[0m")
            
            # Also print live hosts
            print(f"\n\033[93m[ Live Hosts ]\033[0m")
            for host in live_hosts:
                print(f"  • {host}")
            
            return live_hosts, live_hosts_path
    
    print(f"\033[91m[-] No live hosts found\033[0m")
    return None, None

def extract_hosts_from_xml(xml_file):
    """Extract live hosts from nmap XML output"""
    live_hosts = []
    try:
        with open(xml_file, 'r') as f:
            content = f.read()
        
        # Find all hosts with status="up"
        pattern = r'<host>[\s\S]*?<status state="up"[\s\S]*?<address addr="([^"]+)" addrtype="ipv4"'
        matches = re.findall(pattern, content)
        
        for ip in matches:
            if ip not in live_hosts:
                live_hosts.append(ip)
    
    except Exception as e:
        print(f"\033[91m[-] Error parsing XML: {e}\033[0m")
    
    return live_hosts

def scan_live_hosts(live_hosts_file, output_dir):
    """Scan all live hosts with full port scan + script scan"""
    print(f"\n\033[95m{'='*80}\033[0m")
    print(f"\033[95m[ STAGE 2: PORT & SERVICE SCANNING ]\033[0m")
    print(f"\033[95m{'='*80}\033[0m")
    
    if not os.path.exists(live_hosts_file):
        print(f"\033[91m[-] Live hosts file not found: {live_hosts_file}\033[0m")
        return
    
    # Create scans folder
    scans_dir = os.path.join(output_dir, "detailed_scans")
    os.makedirs(scans_dir, exist_ok=True)
    
    # Create web discovery XML for EyeWitness (will aggregate all scans)
    web_discovery_xml = os.path.join(output_dir, "web-discovery.xml")
    
    # Read live hosts
    with open(live_hosts_file, 'r') as f:
        hosts = [line.strip() for line in f if line.strip()]
    
    print(f"\033[93m[+] Starting detailed scans for {len(hosts)} live hosts\033[0m")
    
    all_xml_parts = []
    
    for i, host in enumerate(hosts, 1):
        print(f"\n\033[96m{'#'*80}\033[0m")
        print(f"\033[96m[ SCANNING HOST {i}/{len(hosts)}: {host} ]\033[0m")
        print(f"\033[96m{'#'*80}\033[0m")
        
        # Create host-specific directory
        host_dir = os.path.join(scans_dir, host)
        os.makedirs(host_dir, exist_ok=True)
        
        # Phase 1: Full port scan
        print(f"\n\033[94m[ Phase 1: Full port discovery ]\033[0m")
        phase1_output = os.path.join(host_dir, "port_scan")
        cmd = f"sudo nmap -p- --min-rate=10000 {host} -oA {phase1_output}"
        if not run_command_real_time(cmd):
            continue
        
        # Extract open ports from the NORMAL nmap output (not gnmap)
        open_ports = extract_ports_from_nmap(f"{phase1_output}.nmap")
        
        if not open_ports:
            print(f"\033[93m[!] No open ports found for {host}\033[0m")
            continue
        
        ports_string = ','.join(open_ports)
        print(f"\033[92m[+] Found {len(open_ports)} open ports: {ports_string}\033[0m")
        
        # Phase 2: Script and version scan
        print(f"\n\033[94m[ Phase 2: Script & version scan ]\033[0m")
        phase2_output = os.path.join(host_dir, "script_scan")
        cmd = f"sudo nmap -sC -sV -O -p {ports_string} {host} -oA {phase2_output}"
        if not run_command_real_time(cmd):
            continue
        
        # Collect XML output for EyeWitness
        xml_file = f"{phase2_output}.xml"
        if os.path.exists(xml_file):
            try:
                with open(xml_file, 'r') as f:
                    xml_content = f.read()
                    # Extract just the host part
                    host_xml_match = re.search(r'<host>[\s\S]*?</host>', xml_content)
                    if host_xml_match:
                        all_xml_parts.append(host_xml_match.group())
            except Exception as e:
                print(f"\033[91m[-] Error reading XML: {e}\033[0m")
        
        print(f"\033[92m[✓] Completed scan for {host}\033[0m")
        print(f"\033[92m[+] Files saved in: {host_dir}/\033[0m")
    
    # Create combined XML for EyeWitness
    if all_xml_parts:
        create_combined_xml(all_xml_parts, web_discovery_xml)
        print(f"\n\033[92m[+] EyeWitness XML created: {web_discovery_xml}\033[0m")

def extract_ports_from_nmap(nmap_file):
    """Extract open ports from .nmap file - SIMPLER AND MORE RELIABLE"""
    open_ports = []
    try:
        with open(nmap_file, 'r') as f:
            content = f.read()
        
        # Parse the standard nmap output format
        # Lines look like: "21/tcp   open  ftp"
        # or: "PORT      STATE SERVICE"
        
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            
            # Match lines like: "21/tcp    open  ftp"
            # The format is: PORT/tcp  STATE SERVICE
            match = re.match(r'^(\d+)/tcp\s+(open|filtered|closed)\s+', line)
            if match:
                port = match.group(1)
                state = match.group(2)
                if state == 'open':
                    open_ports.append(port)
        
        # Alternative method: Look for port sections
        if not open_ports:
            # Look for the port listing section
            in_port_section = False
            for line in lines:
                if "PORT" in line and "STATE" in line and "SERVICE" in line:
                    in_port_section = True
                    continue
                
                if in_port_section:
                    if not line.strip():  # Empty line ends port section
                        break
                    
                    # Parse port lines
                    parts = line.split()
                    if len(parts) >= 3 and '/' in parts[0]:
                        port_part = parts[0]  # e.g., "21/tcp"
                        state = parts[1]     # e.g., "open"
                        
                        if state == 'open':
                            port = port_part.split('/')[0]
                            open_ports.append(port)
        
        # Remove duplicates and sort numerically
        open_ports = sorted(set(open_ports), key=int)
        
    except Exception as e:
        print(f"\033[91m[-] Error parsing nmap file {nmap_file}: {e}\033[0m")
        # Debug: print the actual content
        try:
            with open(nmap_file, 'r') as f:
                print(f"\033[93m[Debug] First few lines of {nmap_file}:\033[0m")
                for i, line in enumerate(f):
                    if i < 10:
                        print(f"  {line.rstrip()}")
                    else:
                        break
        except:
            pass
    
    return open_ports

def create_combined_xml(xml_parts, output_file):
    """Create combined XML file for EyeWitness"""
    xml_header = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<nmaprun scanner="nmap" args="nmap -sC -sV -O" start="{timestamp}" version="7.94" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="{num_services}" services="{services}"/>
<verbose level="0"/>
<debugging level="0"/>
""".format(
        timestamp=str(int(time.time())),
        num_services=len(xml_parts),
        services="1-65535"
    )
    
    xml_footer = "</nmaprun>"
    
    with open(output_file, 'w') as f:
        f.write(xml_header)
        for part in xml_parts:
            f.write(f"{part}\n")
        f.write(xml_footer)

def main():
    parser = argparse.ArgumentParser(
        description='Automated Nmap Scanner with Real-time Output',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Single target:      %(prog)s 192.168.1.100
  Multiple targets:   %(prog)s 192.168.1.100 192.168.1.101
  IP range:           %(prog)s 10.10.10.1-50
  CIDR:               %(prog)s 10.10.10.0/24
  From file:          %(prog)s -iL targets.txt
        """
    )
    
    parser.add_argument('targets', nargs='*', help='Target(s) to scan')
    parser.add_argument('-iL', '--input-file', help='Input file containing targets')
    parser.add_argument('--no-ping', action='store_true', 
                       help='Skip host ping scan phase')
    parser.add_argument('--no-sudo', action='store_true',
                       help='Run without sudo (some features disabled)')
    
    args = parser.parse_args()
    
    # Check if nmap is available
    if subprocess.run(["which", "nmap"], capture_output=True).returncode != 0:
        print("\033[91m[-] Nmap is not installed or not in PATH\033[0m")
        sys.exit(1)
    
    # Get targets
    targets = []
    
    if args.input_file:
        if os.path.exists(args.input_file):
            with open(args.input_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"\033[92m[+] Loaded {len(targets)} targets from {args.input_file}\033[0m")
        else:
            print(f"\033[91m[-] Input file not found: {args.input_file}\033[0m")
            sys.exit(1)
    elif args.targets:
        targets = args.targets
    else:
        parser.print_help()
        sys.exit(1)
    
    if not targets:
        print("\033[91m[-] No targets specified\033[0m")
        sys.exit(1)
    
    # Check for sudo
    if os.geteuid() != 0 and not args.no_sudo:
        print("\033[93m[!] Not running as root. Some features may be limited.\033[0m")
        print("\033[93m[!] Use --no-sudo flag to suppress this warning.\033[0m")
        time.sleep(2)
    
    # Create output directory
    output_dir = create_output_directory()
    
    # Host discovery phase
    live_hosts = []
    live_hosts_file = None
    
    if args.no_ping:
        print(f"\n\033[93m[!] Skipping host discovery phase\033[0m")
        # Treat all targets as live hosts
        live_hosts = targets
        live_hosts_file = os.path.join(output_dir, "all_targets.txt")
        with open(live_hosts_file, 'w') as f:
            for host in live_hosts:
                f.write(f"{host}\n")
        print(f"\033[92m[+] Assuming all {len(live_hosts)} targets are live\033[0m")
    else:
        live_hosts, live_hosts_file = discover_live_hosts(targets, output_dir)
        if not live_hosts:
            print(f"\033[91m[-] No live hosts to scan. Exiting.\033[0m")
            sys.exit(0)
    
    # Detailed scanning phase
    scan_live_hosts(live_hosts_file, output_dir)
    
    # Summary
    print(f"\n\033[95m{'='*80}\033[0m")
    print(f"\033[95m[ SCAN COMPLETE ]\033[0m")
    print(f"\033[95m{'='*80}\033[0m")
    print(f"\033[92m[+] All results saved in: {output_dir}/\033[0m")
    print(f"\033[92m[+] EyeWitness XML: {output_dir}/web-discovery.xml\033[0m")
    print(f"\033[92m[+] Live hosts list: {live_hosts_file}\033[0m")
    print(f"\033[92m[+] Detailed scans: {output_dir}/detailed_scans/\033[0m")

if __name__ == "__main__":
    main()
