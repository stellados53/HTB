#!/usr/bin/env python3
import re
import sys
import argparse
import os
from collections import Counter

def extract_users(input_file):
    """
    Parse the input file and return a list of (localpart, domain) tuples.
    """
    users = []
    # Regex finds "VALID USERNAME:" followed by whitespace then username@domain
    pattern = re.compile(r"VALID USERNAME:\s*([^\s@]+)@([^\s\]\)]+)", re.IGNORECASE)
    with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = pattern.search(line)
            if m:
                local = m.group(1).strip()
                domain = m.group(2).strip()
                users.append((local, domain))
    return users

def choose_domain(domain_list):
    """
    Choose the most common domain seen. Return None if no domains.
    """
    if not domain_list:
        return None
    c = Counter(domain_list)
    return c.most_common(1)[0][0]

def write_output(output_file, domain, locals_list):
    """
    Write domain: on first line, then each username (local part) on its own line.
    """
    with open(output_file, "w", encoding="utf-8") as f:
        if domain:
            f.write(f"{domain}:\n")
        else:
            f.write("unknown_domain:\n")
        for user in locals_list:
            f.write(user + "\n")

def filter_names(names, start_prefix=None, end_suffix=None):
    """
    Return list of names matching the optional start and/or end filters.
    Case-insensitive.
    """
    if start_prefix is None and end_suffix is None:
        return names[:]
    start = start_prefix.lower() if start_prefix else None
    end = end_suffix.lower() if end_suffix else None
    out = []
    for n in names:
        nl = n.lower()
        if start and not nl.startswith(start):
            continue
        if end and not nl.endswith(end):
            continue
        out.append(n)
    return out

def main():
    parser = argparse.ArgumentParser(
        prog="kerbrute_username_extracter.py",
        description="Extract usernames from Kerbrute/Responder output and save them to an output file.\nWrites domain on first line followed by usernames (local parts).",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument("-i", "--input", required=True, help="Input file name (required)")
    parser.add_argument("-o", "--output", required=True, help="Output file name (required)")
    parser.add_argument("-a", "--starts-with", metavar="PREFIX", help="Print to terminal usernames that start with PREFIX (case-insensitive)")
    parser.add_argument("-e", "--ends-with", metavar="SUFFIX", help="Print to terminal usernames that end with SUFFIX (case-insensitive)")

    args = parser.parse_args()

    # Validate input exists
    if not os.path.isfile(args.input):
        print("Input file not found:", args.input)
        sys.exit(1)

    entries = extract_users(args.input)
    if not entries:
        print("No usernames found in input file.")
        # Still create an output with unknown_domain: and exit non-zero
        write_output(args.output, None, [])
        print(f"Created empty output file: {args.output}")
        sys.exit(1)

    locals_list = [t[0] for t in entries]
    domains = [t[1] for t in entries]
    domain = choose_domain(domains)

    # Deduplicate while preserving order
    seen = set()
    unique_locals = []
    for u in locals_list:
        if u not in seen:
            seen.add(u)
            unique_locals.append(u)

    write_output(args.output, domain, unique_locals)
    print(f"Usernames saved to {args.output}")

    # Filtering for terminal output
    if args.starts_with or args.ends_with:
        matched = filter_names(unique_locals, args.starts_with, args.ends_with)
        if matched:
            print("\nMatched usernames:")
            for m in matched:
                print(m)
        else:
            print("\nNo usernames matched the given filter(s).")

if __name__ == "__main__":
    main()
