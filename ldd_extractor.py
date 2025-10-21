#!/usr/bin/env python3
import json
import sys
from pathlib import Path

def extract_users(json_file, output_file):
    """Extract usernames from domain_users.json"""
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        users = set()
        
        # Handle both list and dict structures
        if isinstance(data, list):
            entries = data
        elif isinstance(data, dict):
            entries = data.get('entries', []) or list(data.values())
        else:
            entries = []
        
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            
            # Try multiple possible username fields
            username = (entry.get('sAMAccountName') or 
                       entry.get('name') or 
                       entry.get('cn') or
                       entry.get('attributes', {}).get('sAMAccountName'))
            
            if username:
                # Handle list values
                if isinstance(username, list):
                    username = username[0] if username else None
                
                if username:
                    users.add(username.lower())
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            for user in sorted(users):
                f.write(f"{user}\n")
        
        print(f"[+] Extracted {len(users)} users to {output_file}")
        return len(users)
        
    except Exception as e:
        print(f"[-] Error processing users: {e}")
        return 0

def extract_computers(json_file, output_file):
    """Extract computer FQDNs from domain_computers.json"""
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        computers = set()
        
        # Handle both list and dict structures
        if isinstance(data, list):
            entries = data
        elif isinstance(data, dict):
            entries = data.get('entries', []) or list(data.values())
        else:
            entries = []
        
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            
            # Try to get FQDN (dNSHostName is the full FQDN)
            fqdn = (entry.get('dNSHostName') or 
                   entry.get('attributes', {}).get('dNSHostName'))
            
            if fqdn:
                # Handle list values
                if isinstance(fqdn, list):
                    fqdn = fqdn[0] if fqdn else None
                
                if fqdn:
                    computers.add(fqdn.lower())
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            for computer in sorted(computers):
                f.write(f"{computer}\n")
        
        print(f"[+] Extracted {len(computers)} computers to {output_file}")
        return len(computers)
        
    except Exception as e:
        print(f"[-] Error processing computers: {e}")
        return 0

def main():
    # File paths
    users_json = "domain_users.json"
    computers_json = "domain_computers.json"
    users_output = "users.txt"
    computers_output = "computers.txt"
    
    print("[*] LDAP Domain Dump Extractor")
    print("[*] " + "="*50)
    
    # Check if files exist
    if not Path(users_json).exists():
        print(f"[-] {users_json} not found!")
    else:
        extract_users(users_json, users_output)
    
    if not Path(computers_json).exists():
        print(f"[-] {computers_json} not found!")
    else:
        extract_computers(computers_json, computers_output)
    
    print("[*] Done!")

if __name__ == "__main__":
    main()
