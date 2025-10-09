import re
import sys
import os

def extract_ports(filename):
    ports = []
    with open(filename, "r") as f:
        for line in f:
            # Extract "number/proto"
            match = re.match(r"(\d+)/\w+", line)
            if match:
                ports.append(match.group(1))
    return ports

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("\nFile not found")
        sys.exit(1)

    filename = sys.argv[1]

    if not os.path.isfile(filename):
        print("\nFile not found")
        sys.exit(1)

    ports = extract_ports(filename)
    print("\n")
    print(",".join(ports))
