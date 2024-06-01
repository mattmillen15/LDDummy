import argparse
import os
import subprocess
import sys
import json

def check_write_access(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)
    if not os.access(directory, os.W_OK):
        print(f"Error: The output directory {directory} is not writable.", file=sys.stderr)
        sys.exit(1)

def run_ldapdomaindump(domain, username, password, dc, output_dir):
    cmd = [
        "ldapdomaindump",
        "-u", f"{domain}\\{username}",
        "-p", password,
        dc,
        "-o", output_dir
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"ldapdomaindump completed successfully. Output saved to {output_dir}")
        print(f"Command output: {result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Error: ldapdomaindump command failed with error: {e.stderr}", file=sys.stderr)
        print(f"Full command executed: {' '.join(cmd)}")
        print(f"Command stdout: {e.stdout}")
        print(f"Command stderr: {e.stderr}")
        sys.exit(1)

def extract_and_save_attributes(json_file, attribute, output_file):
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    values = []
    for entry in data:
        if attribute in entry['attributes'] and entry['attributes'][attribute]:
            attr_value = entry['attributes'][attribute]
            if isinstance(attr_value, list):
                values.extend(attr_value)
            else:
                values.append(attr_value)
    
    values = [value.lower() for value in values if value is not None]
    
    with open(output_file, 'w') as f:
        for value in values:
            f.write(f"{value}\n")

def process_output_files(output_dir):
    users_file = os.path.join(output_dir, "domain_users.json")
    computers_file = os.path.join(output_dir, "domain_computers.json")
    
    users_output = os.path.join(output_dir, "users.txt")
    computers_output = os.path.join(output_dir, "computers.txt")
    
    if os.path.exists(users_file):
        extract_and_save_attributes(users_file, 'sAMAccountName', users_output)
        print(f"Processed users output saved to {users_output}")
    else:
        print(f"Error: {users_file} not found", file=sys.stderr)
    
    if os.path.exists(computers_file):
        extract_and_save_attributes(computers_file, 'dNSHostName', computers_output)
        print(f"Processed computers output saved to {computers_output}")
    else:
        print(f"Error: {computers_file} not found", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(description="Wrapper for ldapdomaindump with additional processing.")
    parser.add_argument("-d", "--domain", required=True, help="LDAP domain")
    parser.add_argument("-u", "--username", required=True, help="LDAP username")
    parser.add_argument("-p", "--password", required=True, help="LDAP password")
    parser.add_argument("-dc", required=True, help="IP or hostname of the Domain Controller")
    parser.add_argument("-o", "--output", help="Output directory for ldapdomaindump results [Default: <current-directory>/ldapdomaindump_output]")

    args = parser.parse_args()

    # Check if output directory is provided and writable
    output_dir = args.output if args.output else os.path.join(os.getcwd(), "ldapdomaindump_output")
    check_write_access(output_dir)
    
    run_ldapdomaindump(args.domain, args.username, args.password, args.dc, output_dir)
    process_output_files(output_dir)

if __name__ == "__main__":
    main()
