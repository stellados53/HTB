#!/usr/bin/env python3
"""
Wordlist Combination Generator
Generate combinations of words from a wordlist file with various lengths.
"""

import argparse
import itertools
import sys
from pathlib import Path

def read_wordlist(filename):
    """Read words from file and return as list, filtering empty lines."""
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            words = [line.strip() for line in file if line.strip()]
        return words
    except FileNotFoundError:
        print(f"Error: Input file '{filename}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

def generate_combinations(words, min_length=1, max_length=4):
    """Generate combinations from min_length to max_length."""
    all_combinations = []
    
    for length in range(min_length, max_length + 1):
        # Generate all combinations with repetition for current length
        for combo in itertools.product(words, repeat=length):
            combined_string = ''.join(combo)
            all_combinations.append(combined_string)
    
    return all_combinations

def write_output(combinations, filename):
    """Write combinations to output file."""
    try:
        with open(filename, 'w', encoding='utf-8') as file:
            for combo in combinations:
                file.write(combo + '\n')
        print(f"Generated {len(combinations)} combinations in '{filename}'")
    except Exception as e:
        print(f"Error writing to output file: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Generate word combinations from a wordlist file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate combinations from 1 to 4 words and save to output.txt
  python password_wordlist_gen.py -i suspected_wordlist.txt -o password-wordlist-raw.txt
  
  # Generate combinations from 2 to 3 words only
  python password_wordlist_gen.py -i suspected_wordlist.txt -o password-wordlist-raw.txt --min 2 --max 3
  
  # Generate combinations with custom separator
  python.py -i suspected_wordlist.txt -o password-wordlist-raw.txt --separator "-"
  
Input file format (suspected_wordlist.txt):
  mark
  white
  05
  08
  1998
  sanfransico
  baseball
   # Output file will contain all possible combinations from 1 to 4 words by default.

Post Wordlist Generation
  ls -l /usr/share/hashcat/rules

# changing the passwords chars 
  hashcat --force -r /usr/share/hashcat/rules/best64.rule password.list --stdout | sort -u > best64_password.list
  hashcat --force -r /usr/share/hashcat/rules/rockyou-30000.rule password.list --stdout | sort -u > rockyou-30000_password.list

# extracting certain length from a wordlist
  cat best64_password.list | awk 'length($0) >= 12' > best64_password_12.list
  cat best64_password.list | awk 'length($0) >= 13' > best64_password_13.list
  cat rockyou-30000_password.list | awk 'length($0) >= 12' > rockyou-30000_password_12.list
  cat rockyou-30000_password.list | awk 'length($0) >= 12' > rockyou-30000_password_13.list

"""
    )
    
    parser.add_argument('-i', '--input', required=True, 
                       help='Input file containing wordlist')
    parser.add_argument('-o', '--output', required=True,
                       help='Output file to save combinations')
    parser.add_argument('--min', type=int, default=1,
                       help='Minimum combination length (default: 1)')
    parser.add_argument('--max', type=int, default=4,
                       help='Maximum combination length (default: 4)')
    parser.add_argument('--separator', default='',
                       help='Separator between words (default: empty string)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.min < 1:
        print("Error: Minimum length must be at least 1")
        sys.exit(1)
    
    if args.max < args.min:
        print("Error: Maximum length must be greater than or equal to minimum length")
        sys.exit(1)
    
    # Read wordlist
    print(f"Reading wordlist from '{args.input}'...")
    words = read_wordlist(args.input)
    print(f"Loaded {len(words)} words from input file")
    
    # Generate combinations
    print(f"Generating combinations from length {args.min} to {args.max}...")
    
    all_combinations = []
    for length in range(args.min, args.max + 1):
        combinations_for_length = []
        for combo in itertools.product(words, repeat=length):
            combined_string = args.separator.join(combo)
            combinations_for_length.append(combined_string)
        
        all_combinations.extend(combinations_for_length)
        print(f"  Length {length}: {len(combinations_for_length)} combinations")
    
    # Write output
    print(f"Writing {len(all_combinations)} total combinations to '{args.output}'...")
    write_output(all_combinations, args.output)

if __name__ == "__main__":
    main()
