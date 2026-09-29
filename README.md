# LDDummy
Just a dumb wrapper for ldapdomaindump to get a plain user and computer list....

Shameless rip off of https://github.com/fin3ss3g0d/ldd_json_parser.sh, but built to be a one hitta quitta...

Auto-negotiates authentication — handles **LDAP signing**, **channel binding** (EPA), and **pass-the-hash** automatically. Just provide credentials and it figures out the rest.

___
# Usage: 
```zsh
# Standard — auto-negotiates LDAP → LDAPS → Kerberos as needed
LDDummy.py -u <username> -p <password> -d <domain> -dc <dc-ip>

# Pass-the-hash — impacket NTLM bind, auto-falls back to Kerberos
LDDummy.py -u <username> -H <LM:NT> -d <domain> -dc <dc-ip>

# Force Kerberos — bypasses LDAP signing AND channel binding (EPA)
LDDummy.py -u <username> -p <password> -d <domain> -dc <dc-ip> -k [--dc-host <dc-fqdn>]

# Kerberos with existing ccache
LDDummy.py -u <username> -d <domain> -dc <dc-ip> --ccache <user.ccache>

# Force LDAPS (port 636)
LDDummy.py -u <username> -p <password> -d <domain> -dc <dc-ip> --ldaps
```

| Flag | Description |
|------|-------------|
| `-p` | Plaintext password |
| `-H` | NTLM hashes (`LM:NT` or `:NT`) — pass-the-hash via impacket |
| `--ldaps` | Force LDAPS (port 636) |
| `-k` / `--kerberos` | Force Kerberos auth (GSSAPI) |
| `--dc-host` | DC FQDN for Kerberos SPN (auto-resolved via reverse DNS if omitted) |
| `--ccache` | Use an existing Kerberos ccache file |
| `-o` | Output directory (default: `./ldapdomaindump_output`) |

### Auth negotiation

**With `-p` (password):**
1. Plain LDAP via `ldapdomaindump`
2. If signing enforced → retry LDAPS
3. If LDAPS fails → auto-request TGT and Kerberos bind via impacket

**With `-H` (hashes):**
1. NTLM bind via impacket (handles signing + pass-the-hash)
2. If channel binding enforced → auto-request TGT (overpass-the-hash) and Kerberos bind

**With `-k` or `--ccache`:**
1. Kerberos bind directly via impacket

DC hostname for Kerberos SPN is auto-resolved via reverse DNS. If reverse DNS fails, provide `--dc-host`.

* Or if you already have LdapDomainDump output (.json files), use the ldd_extractor.py script to extract lowercase users.txt and computers.txt
---  
![image](https://github.com/mattmillen15/LDDummy/assets/68832392/f575e731-ce0c-461e-810e-dd71aaec4ecc)
___
![image](https://github.com/mattmillen15/LDDummy/assets/68832392/a99618a5-0b50-4f17-951c-e5589e3962a1)
___
