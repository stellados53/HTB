import subprocess
import ipaddress
import platform
import threading
from concurrent.futures import ThreadPoolExecutor
import time

def ping_host(ip, timeout=1):
    """
    Ping a single host with 1 packet
    Returns True if host is up, False otherwise
    """
    # Determine the ping command based on OS
    param = "-n" if platform.system().lower() == "windows" else "-c"
    
    # Build the command: ping with 1 packet and short timeout
    command = ["ping", param, "1", "-W" if platform.system().lower() == "windows" else "-w", 
              str(timeout * 1000) if platform.system().lower() == "windows" else str(timeout), 
              str(ip)]
    
    try:
        # Run ping command and capture output
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 1)
        
        # Check return code (0 typically means success)
        if result.returncode == 0:
            return True, ip
        else:
            return False, ip
    except (subprocess.TimeoutExpired, Exception):
        return False, ip

def scan_subnet(subnet, max_threads=50):
    """
    Scan a subnet for active hosts
    """
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        print(f"Scanning subnet: {subnet}")
        print(f"Total IPs to scan: {network.num_addresses}")
        print("-" * 50)
        
        active_hosts = []
        total_scanned = 0
        
        # Use thread pool for concurrent scanning
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit all ping tasks
            future_to_ip = {executor.submit(ping_host, str(ip)): ip for ip in network.hosts()}
            
            # Process results as they complete
            for future in future_to_ip:
                total_scanned += 1
                is_up, ip = future.result()
                if is_up:
                    active_hosts.append(ip)
                    print(f"✓ {ip} is UP")
        
        return active_hosts
        
    except ValueError as e:
        print(f"Error: Invalid subnet format - {e}")
        return []

def main():
    # Get subnet from user
    subnet = input("Enter subnet to scan (e.g., 192.168.1.0/24): ").strip()
    
    start_time = time.time()
    
    # Scan the subnet
    active_hosts = scan_subnet(subnet)
    
    end_time = time.time()
    
    # Print results
    print("\n" + "=" * 50)
    print("SCAN RESULTS:")
    print("=" * 50)
    print(f"Active hosts found: {len(active_hosts)}")
    for host in sorted(active_hosts):
        print(f"  {host}")
    print(f"Scan completed in {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
