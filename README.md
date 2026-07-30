# LDDummy
Just a dumb wrapper for ldapdomaindump to get a plain user and computer list....

Shameless rip off of https://github.com/fin3ss3g0d/ldd_json_parser.sh, but built to be a one hitta quitta...

Now with support for DCs that enforce **LDAP signing** and **channel binding** (EPA).
___
# Usage: 
```zsh
# Standard NTLM (auto-falls back to LDAPS if signing is enforced)
LDDummy.py -u <username> -p <password> -d <domain> -dc <dc-ip> [-o <output_directory>]

# Force LDAPS (port 636) — satisfies signing enforcement
LDDummy.py -u <username> -p <password> -d <domain> -dc <dc-ip> --ldaps

# Kerberos — bypasses LDAP signing AND channel binding (EPA/KB5021130)
LDDummy.py -u <username> -p <password> -d <domain> -dc <dc-ip> -k [--dc-host <dc-fqdn>]

# Kerberos with existing ccache (e.g. from getTGT.py or a prior run)
LDDummy.py -u <username> -d <domain> -dc <dc-ip> -k --ccache <user.ccache>

# Pass-the-hash + Kerberos (overpass-the-hash)
LDDummy.py -u <username> -H <LM:NT> -d <domain> -dc <dc-ip> -k --dc-host <dc-fqdn>
```

| Flag | Description |
|------|-------------|
| `-p` | Plaintext password |
| `-H` | NTLM hashes (`LM:NT` or `:NT`) |
| `--ldaps` | Force LDAPS (port 636) |
| `-k` / `--kerberos` | Kerberos auth (GSSAPI) — best path when signing/EPA enforced |
| `--dc-host` | DC FQDN — needed for Kerberos SPN (`ldap/<fqdn>`) |
| `--ccache` | Use an existing Kerberos ccache file |
| `-o` | Output directory (default: `./ldapdomaindump_output`) |

* Or if you already have LdapDomainDump output (.json files), use the ldd_extractor.py script to extract lowercase users.txt and computers.txt
---  
![image](https://github.com/mattmillen15/LDDummy/assets/68832392/f575e731-ce0c-461e-810e-dd71aaec4ecc)
___
![image](https://github.com/mattmillen15/LDDummy/assets/68832392/a99618a5-0b50-4f17-951c-e5589e3962a1)
___
