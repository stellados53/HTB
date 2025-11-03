import subprocess
import ipaddress
import platform
import threading
from concurrent.futures import ThreadPoolExecutor
import time
import sys
import select

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
        all_ips = list(network.hosts())
        total_ips = len(all_ips)
        
        print(f"Scanning subnet: {subnet}")
        print(f"Total IPs to scan: {total_ips}")
        print("Press Enter to see progress...")
        print("-" * 50)
        
        active_hosts = []
        completed_ips = 0
        lock = threading.Lock()
        
        # Function to update progress and check for user input
        def update_progress():
            nonlocal completed_ips
            with lock:
                completed_ips += 1
                
            # Check if user pressed Enter
            if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                line = sys.stdin.readline()
                if line:  # Enter was pressed
                    with lock:
                        progress = (completed_ips / total_ips) * 100
                        remaining_ips = total_ips - completed_ips
                        print(f"\nProgress: {progress:.1f}% ({completed_ips}/{total_ips} completed, {remaining_ips} remaining)")
                        print("Press Enter again for updated progress...")
        
        # Worker function that wraps ping_host
        def worker(ip):
            is_up, ip_addr = ping_host(ip)
            update_progress()  # Update progress after each ping
            return is_up, ip_addr
        
        # Use thread pool for concurrent scanning
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit all ping tasks
            future_to_ip = {executor.submit(worker, str(ip)): ip for ip in all_ips}
            
            # Process results as they complete
            for future in future_to_ip:
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
