import argparse
import atexit
import json
import os
import ssl
import subprocess
import sys
import tempfile

try:
    import ldap3
    from ldap3 import Server, Connection, NTLM, SASL, GSSAPI, Tls, ALL
    from ldapdomaindump import domainDumper, domainDumpConfig
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False


def check_write_access(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)
    if not os.access(directory, os.W_OK):
        print(f"[-] Output directory {directory} is not writable.", file=sys.stderr)
        sys.exit(1)


def _is_signing_error(text):
    t = text.lower()
    return ("strongerauth" in t or "00002028" in t or "80090346" in t
            or "confidentiality" in t or "integrity required" in t
            or "data 80090346" in t)


def _ldapdomaindump_subprocess(domain, username, credential, dc, output_dir, ldaps=False):
    host = f"ldaps://{dc}" if ldaps else dc
    cmd = [
        "ldapdomaindump",
        "-u", f"{domain}\\{username}",
        "-p", credential,
        host,
        "-o", output_dir,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    combined = result.stdout + result.stderr
    if result.returncode != 0 or _is_signing_error(combined):
        if _is_signing_error(combined):
            return False, "signing"
        return False, result.stderr.strip() or result.stdout.strip()
    print(f"[+] ldapdomaindump completed. Output saved to {output_dir}")
    return True, None


def _obtain_tgt(username, password, hashes, domain, dc_ip):
    """Request a Kerberos TGT via impacket. Returns None when an existing ccache should be used."""
    try:
        from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
        from impacket.krb5.types import Principal
        from impacket.krb5 import constants as kconst
        from impacket.krb5.ccache import CCache
        from binascii import unhexlify
    except ImportError:
        print("[-] impacket not installed: pip3 install impacket", file=sys.stderr)
        sys.exit(1)

    lm, nt = "", ""
    if hashes:
        parts = hashes.split(":", 1)
        lm, nt = (parts[0], parts[1]) if len(parts) == 2 else ("", parts[0])

    realm = domain.upper()
    principal = Principal(username, type=kconst.PrincipalNameType.NT_PRINCIPAL.value)
    how = "NT hash (pass-the-hash)" if hashes else "password"
    print(f"[*] Requesting TGT for {username}@{realm} via {how} (KDC {dc_ip})...")
    try:
        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
            principal, password or "", realm,
            unhexlify(lm) if lm else b"",
            unhexlify(nt) if nt else b"",
            "", dc_ip)
    except KerberosError as ke:
        print(f"[-] Kerberos pre-auth failed: {ke}", file=sys.stderr)
        sys.exit(1)

    print("[+] TGT acquired.")
    cc = CCache()
    cc.fromTGT(tgt, oldSessionKey, sessionKey)
    fd, path = tempfile.mkstemp(suffix=".ccache", prefix="lddummy_")
    os.close(fd)
    cc.saveFile(path)
    atexit.register(lambda p=path: os.path.exists(p) and os.remove(p))
    return path


def _ldapdomaindump_kerberos(domain, username, password, hashes, dc_ip, dc_host,
                              output_dir, ccache=None):
    """Dump via ldap3 GSSAPI (Kerberos) — satisfies signing and bypasses EPA."""
    if not HAS_LDAP3:
        print("[-] ldap3/ldapdomaindump not installed.", file=sys.stderr)
        sys.exit(1)

    # Resolve credentials
    if ccache:
        os.environ["KRB5CCNAME"] = os.path.abspath(ccache)
        print(f"[*] Using existing ccache: {ccache}")
    elif password or hashes:
        ccache_path = _obtain_tgt(username, password, hashes, domain, dc_ip)
        os.environ["KRB5CCNAME"] = os.path.abspath(ccache_path)
    elif os.environ.get("KRB5CCNAME"):
        print(f"[*] Using ccache from KRB5CCNAME: {os.environ['KRB5CCNAME']}")
    else:
        print("[-] Kerberos requires -p, -H, --ccache, or KRB5CCNAME.", file=sys.stderr)
        sys.exit(1)

    # Kerberos needs the FQDN for the ldap/<fqdn> SPN — IP won't work
    target = dc_host or dc_ip
    if target == dc_ip and not dc_host:
        print("[!] No --dc-host supplied; using IP for the SPN. "
              "Pass --dc-host <fqdn> if the bind fails.")

    tls = ldap3.Tls(validate=ssl.CERT_NONE)
    server = Server(target, port=389, use_ssl=False, tls=tls, get_info=ALL)
    print(f"[*] Connecting to {target}:389 via Kerberos (GSSAPI)...")
    try:
        conn = Connection(server, authentication=SASL, sasl_mechanism=GSSAPI,
                          auto_bind=True, check_names=False)
    except Exception as e:
        print(f"[-] Kerberos LDAP bind failed: {e}", file=sys.stderr)
        sys.exit(1)

    print("[+] Kerberos LDAP bind successful.")

    config = domainDumpConfig()
    config.basepath = output_dir
    dumper = domainDumper(server, conn, config)
    dumper.domainDump()
    print(f"[+] ldapdomaindump completed. Output saved to {output_dir}")


def extract_and_save_attributes(json_file, attribute, output_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    values = []
    for entry in data:
        attrs = entry.get('attributes', entry)
        val = attrs.get(attribute)
        if val:
            if isinstance(val, list):
                values.extend(val)
            else:
                values.append(val)

    values = [v.lower() for v in values if v]
    with open(output_file, 'w') as f:
        for v in values:
            f.write(f"{v}\n")


def process_output_files(output_dir):
    for filename, attribute, label in [
        ("domain_users.json", "sAMAccountName", "users.txt"),
        ("domain_computers.json", "dNSHostName", "computers.txt"),
    ]:
        src = os.path.join(output_dir, filename)
        dst = os.path.join(output_dir, label)
        if os.path.exists(src):
            extract_and_save_attributes(src, attribute, dst)
            print(f"[+] Extracted {label} -> {dst}")
        else:
            print(f"[-] {src} not found", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Wrapper for ldapdomaindump — with LDAPS and Kerberos support "
                    "for DCs that enforce LDAP signing / channel binding.")
    parser.add_argument("-d", "--domain", required=True, help="LDAP domain")
    parser.add_argument("-u", "--username", required=True, help="LDAP username")
    parser.add_argument("-p", "--password", default=None, help="Password")
    parser.add_argument("-H", "--hashes", default=None,
                        help="NTLM hashes (LM:NT or :NT)")
    parser.add_argument("-dc", required=True,
                        help="IP or hostname of the Domain Controller")
    parser.add_argument("--dc-host", default=None,
                        help="FQDN of the DC — required for Kerberos SPN resolution")
    parser.add_argument("-o", "--output", default=None,
                        help="Output directory [default: ./ldapdomaindump_output]")
    parser.add_argument("--ldaps", action="store_true",
                        help="Force LDAPS (port 636) — satisfies signing enforcement")
    parser.add_argument("-k", "--kerberos", action="store_true",
                        help="Use Kerberos (GSSAPI) — bypasses signing and channel binding")
    parser.add_argument("--ccache", default=None,
                        help="Path to an existing Kerberos ccache file")

    args = parser.parse_args()

    if not args.password and not args.hashes and not args.kerberos and not args.ccache:
        if not os.environ.get("KRB5CCNAME"):
            parser.error("Provide -p PASSWORD, -H HASHES, -k (Kerberos), or --ccache.")

    output_dir = args.output or os.path.join(os.getcwd(), "ldapdomaindump_output")
    check_write_access(output_dir)

    # ── Kerberos path ──────────────────────────────────────────────────────────
    if args.kerberos or args.ccache:
        _ldapdomaindump_kerberos(
            args.domain, args.username, args.password, args.hashes,
            args.dc, args.dc_host, output_dir, ccache=args.ccache)
        process_output_files(output_dir)
        return

    # ── NTLM path (plain LDAP or LDAPS) ───────────────────────────────────────
    credential = args.password or args.hashes
    success, err = _ldapdomaindump_subprocess(
        args.domain, args.username, credential, args.dc, output_dir, ldaps=args.ldaps)

    if not success:
        if err == "signing" and not args.ldaps:
            print("[*] DC enforces LDAP signing / channel binding.")
            print("[*] Retrying over LDAPS (port 636)...")
            success, err = _ldapdomaindump_subprocess(
                args.domain, args.username, credential, args.dc, output_dir, ldaps=True)
            if not success:
                print(f"[-] LDAPS also failed: {err}")
                print("[!] Use -k / --kerberos to bypass signing and channel binding.")
                sys.exit(1)
        else:
            print(f"[-] ldapdomaindump failed: {err}", file=sys.stderr)
            sys.exit(1)

    process_output_files(output_dir)


if __name__ == "__main__":
    main()
