#!/usr/bin/env python3
"""
Username Anarchy - Efficient username generator from names
"""

import argparse
import sys
from typing import List, Set

def generate_username_variations(first_name: str, last_name: str) -> Set[str]:
    """Generate all possible username variations for a given first and last name."""
    usernames = set()
    
    # Clean and prepare names
    first = first_name.lower().strip()
    last = last_name.lower().strip()
    
    first_initial = first[0] if first else ''
    last_initial = last[0] if last else ''
    
    # Basic combinations
    usernames.update([
        first,                                  # ben
        last,                                   # williamson
        first + last,                           # benwilliamson
        last + first,                           # williamsonben
        first_initial + last,                   # bwilliamson
        last + first_initial,                   # williamsonb
        first_initial + last_initial,           # bw
        last_initial + first_initial,           # wb
    ])
    
    # Dot separated combinations
    usernames.update([
        f"{first}.{last}",                      # ben.williamson
        f"{last}.{first}",                      # williamson.ben
        f"{first_initial}.{last}",              # b.williamson
        f"{last}.{first_initial}",              # williamson.b
        f"{first}.{last_initial}",              # ben.w
        f"{last_initial}.{first}",              # w.ben
    ])
    
    # Truncated last name variations (3-7 characters)
    for length in range(3, 8):
        if len(last) >= length:
            truncated = last[:length]
            usernames.update([
                first + truncated,              # benwill, benwilli, etc.
                first_initial + truncated,      # bwill, bwilli, etc.
                truncated + first,              # willben, williben, etc.
                truncated + first_initial,      # willb, willib, etc.
            ])
    
    # First name with truncated last name initials
    for i in range(1, min(4, len(last) + 1)):
        partial_last = last[:i]
        usernames.add(first + partial_last)     # benw, benwi, etc.
    
    # Additional common patterns
    if len(first) > 1:
        usernames.add(first_initial + last)     # bwilliamson (duplicate but explicit)
        usernames.add(first[:3] + last)         # benwilliamson (similar to full)
    
    if len(last) > 1:
        usernames.add(first + last[:3])         # benwil
        usernames.add(first_initial + last[:4]) # bwill
    
    return usernames

def process_names(input_file: str, output_file: str) -> None:
    """Process input file and generate username wordlist."""
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading input file: {e}")
        sys.exit(1)
    
    all_usernames = set()
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Split name into parts
        parts = line.split()
        if len(parts) < 2:
            continue  # Skip lines without both first and last name
        
        first_name = parts[0]
        last_name = ' '.join(parts[1:])  # Handle multiple last names
        
        # Generate variations for this name
        variations = generate_username_variations(first_name, last_name)
        all_usernames.update(variations)
    
    # Write to output file
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for username in sorted(all_usernames):
                f.write(username + '\n')
        print(f"Generated {len(all_usernames)} unique usernames in '{output_file}'")
    except Exception as e:
        print(f"Error writing output file: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description='Generate username variations from names',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -i names.txt -o usernames.txt
  cat names.txt | %(prog)s -o usernames.txt
        '''
    )
    
    parser.add_argument('-i', '--input', dest='input_file',
                       help='Input file containing names (one per line)')
    parser.add_argument('-o', '--output', dest='output_file', required=True,
                       help='Output file for generated usernames')
    
    args = parser.parse_args()
    
    # Check if we have input from stdin if no input file provided
    if not args.input_file and not sys.stdin.isatty():
        # Read from stdin
        lines = sys.stdin.read().splitlines()
        all_usernames = set()
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            parts = line.split()
            if len(parts) < 2:
                continue
                
            first_name = parts[0]
            last_name = ' '.join(parts[1:])
            variations = generate_username_variations(first_name, last_name)
            all_usernames.update(variations)
        
        # Write to output file
        with open(args.output_file, 'w', encoding='utf-8') as f:
            for username in sorted(all_usernames):
                f.write(username + '\n')
        print(f"Generated {len(all_usernames)} unique usernames in '{args.output_file}'")
    
    elif args.input_file:
        process_names(args.input_file, args.output_file)
    else:
        parser.print_help()
        print("\nError: Either provide an input file or pipe data to stdin.")
        sys.exit(1)

if __name__ == '__main__':
    main()
