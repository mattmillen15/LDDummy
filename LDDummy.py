import argparse
import json
import os
import socket
import subprocess
import sys


def check_write_access(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)
    if not os.access(directory, os.W_OK):
        print(f"[-] Output directory {directory} is not writable.", file=sys.stderr)
        sys.exit(1)


def _is_signing_error(text):
    t = text.lower()
    return ("strongerauth" in t or "00002028" in t or "80090346" in t
            or "confidentiality" in t or "integrity required" in t)


def _resolve_dc_host(dc, domain):
    """Resolve DC FQDN for Kerberos SPN via reverse DNS."""
    try:
        socket.inet_aton(dc)
    except socket.error:
        return dc
    try:
        hostname, _, _ = socket.gethostbyaddr(dc)
        if hostname and '.' in hostname:
            return hostname
    except Exception:
        pass
    return None


def _parse_hashes(hashes):
    if not hashes:
        return "", ""
    parts = hashes.split(":", 1)
    return (parts[0], parts[1]) if len(parts) == 2 else ("", parts[0])


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
    """Request a TGT via impacket and return the dict for kerberosLogin(TGT=...)."""
    try:
        from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
        from impacket.krb5.types import Principal
        from impacket.krb5 import constants as kconst
        from binascii import unhexlify
    except ImportError:
        print("[-] impacket not installed: pip3 install impacket", file=sys.stderr)
        sys.exit(1)

    lm, nt = _parse_hashes(hashes)
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
    return {"KDC_REP": tgt, "cipher": cipher, "sessionKey": sessionKey}


def _get_base_dn(ic, domain):
    """Read defaultNamingContext from RootDSE; fall back to constructing from domain."""
    try:
        from impacket.ldap.ldapasn1 import Scope as LDAPScope
        resp = ic.search(
            searchBase="", searchFilter="(objectClass=*)",
            scope=LDAPScope("baseObject"),
            attributes=["defaultNamingContext"])
        for entry in resp:
            try:
                for a in entry["attributes"]:
                    if str(a["type"]) == "defaultNamingContext":
                        return str(a["vals"][0])
            except Exception:
                continue
    except Exception:
        pass
    return ",".join(f"DC={p}" for p in domain.split("."))


def _impacket_search(ic, base, flt, attrs):
    """Paged LDAP search via impacket; returns list of attr dicts with bytes values."""
    from impacket.ldap.ldapasn1 import SimplePagedResultsControl
    try:
        from impacket.ldap.ldap import LDAPSearchError
    except ImportError:
        LDAPSearchError = Exception

    controls = [SimplePagedResultsControl(size=500)]
    try:
        raw = ic.search(searchBase=base, searchFilter=flt,
                        attributes=attrs, searchControls=controls)
    except LDAPSearchError as e:
        raw = e.getAnswers()
    except Exception as e:
        print(f"[-] LDAP search error: {e}", file=sys.stderr)
        return []

    results = []
    for entry in raw:
        try:
            ad = {}
            for a in entry["attributes"]:
                ad[str(a["type"])] = [bytes(v) for v in a["vals"]]
            results.append(ad)
        except Exception:
            continue
    return results


def _impacket_dump(ic, domain, output_dir):
    """Dump users and computers from an authenticated impacket LDAPConnection."""
    base_dn = _get_base_dn(ic, domain)
    print(f"[*] Base DN: {base_dn}")

    print("[*] Enumerating users...")
    user_entries = _impacket_search(
        ic, base_dn,
        "(&(objectClass=user)(!(objectClass=computer)))",
        ["sAMAccountName"])
    users = sorted({
        bytes(ad["sAMAccountName"][0]).decode(errors="replace").lower()
        for ad in user_entries if "sAMAccountName" in ad
    })
    users_file = os.path.join(output_dir, "users.txt")
    with open(users_file, "w") as f:
        f.write("\n".join(users) + ("\n" if users else ""))
    print(f"[+] {len(users)} users -> {users_file}")

    print("[*] Enumerating computers...")
    comp_entries = _impacket_search(
        ic, base_dn,
        "(objectClass=computer)",
        ["dNSHostName"])
    computers = sorted({
        bytes(ad["dNSHostName"][0]).decode(errors="replace").lower()
        for ad in comp_entries if "dNSHostName" in ad
    })
    comp_file = os.path.join(output_dir, "computers.txt")
    with open(comp_file, "w") as f:
        f.write("\n".join(computers) + ("\n" if computers else ""))
    print(f"[+] {len(computers)} computers -> {comp_file}")


def _dump_ntlm_impacket(domain, username, password, hashes, dc_ip, output_dir):
    """NTLM LDAP bind via impacket — handles signing and pass-the-hash."""
    try:
        from impacket.ldap import ldap as ildap
    except ImportError:
        return False, "impacket not installed"

    lm, nt = _parse_hashes(hashes)
    how = "NT hash" if hashes else "password"
    print(f"[*] Trying impacket NTLM bind ({how})...")
    try:
        ic = ildap.LDAPConnection(f"ldap://{dc_ip}", "", dc_ip)
        ic.login(username, password or "", domain, lmhash=lm, nthash=nt)
    except Exception as e:
        err_text = str(e)
        if _is_signing_error(err_text):
            return False, "signing"
        return False, err_text

    print("[+] NTLM LDAP bind successful.")
    _impacket_dump(ic, domain, output_dir)
    return True, None


def _dump_kerberos(domain, username, password, hashes, dc_ip, dc_host, output_dir, ccache=None):
    """Kerberos LDAP dump via impacket — satisfies signing and bypasses EPA/channel binding."""
    try:
        from impacket.ldap import ldap as ildap
    except ImportError:
        print("[-] impacket not installed: pip3 install impacket", file=sys.stderr)
        sys.exit(1)

    tgt_dict = None
    lm, nt = _parse_hashes(hashes)

    if ccache:
        os.environ["KRB5CCNAME"] = os.path.abspath(ccache)
        print(f"[*] Using existing ccache: {ccache}")
    elif password or hashes:
        tgt_dict = _obtain_tgt(username, password, hashes, domain, dc_ip)
    elif os.environ.get("KRB5CCNAME"):
        print(f"[*] Using ccache from KRB5CCNAME: {os.environ['KRB5CCNAME']}")
    else:
        print("[-] Kerberos requires -p, -H, --ccache, or KRB5CCNAME.", file=sys.stderr)
        sys.exit(1)

    target = dc_host or dc_ip
    url = f"ldap://{target}"
    print(f"[*] Connecting to {target}:389 via Kerberos...")
    try:
        ic = ildap.LDAPConnection(url, "", dc_ip)
        ic.kerberosLogin(username, password or "", domain,
                         lmhash=lm, nthash=nt, aesKey="",
                         kdcHost=dc_ip, TGT=tgt_dict,
                         useCache=(tgt_dict is None))
    except Exception as e:
        print(f"[-] Kerberos LDAP bind failed: {e}", file=sys.stderr)
        sys.exit(1)

    print("[+] Kerberos LDAP bind successful.")
    _impacket_dump(ic, domain, output_dir)


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


def _auto_kerberos(domain, username, password, hashes, dc, dc_host, output_dir):
    """Auto-escalate to Kerberos, resolving DC hostname if needed."""
    host = dc_host or _resolve_dc_host(dc, domain)
    if not host:
        print("[-] Cannot resolve DC hostname for Kerberos SPN.", file=sys.stderr)
        print("[!] Re-run with --dc-host <dc-fqdn>.", file=sys.stderr)
        sys.exit(1)
    _dump_kerberos(domain, username, password, hashes, dc, host, output_dir)


def main():
    parser = argparse.ArgumentParser(
        description="LDAP domain dump tool — auto-negotiates auth method "
                    "(NTLM, LDAPS, Kerberos) to handle signing and channel binding.")
    parser.add_argument("-d", "--domain", required=True, help="LDAP domain")
    parser.add_argument("-u", "--username", required=True, help="LDAP username")
    parser.add_argument("-p", "--password", default=None, help="Password")
    parser.add_argument("-H", "--hashes", default=None,
                        help="NTLM hashes (LM:NT or :NT) — pass-the-hash via impacket")
    parser.add_argument("-dc", required=True,
                        help="IP or hostname of the Domain Controller")
    parser.add_argument("--dc-host", default=None,
                        help="FQDN of the DC for Kerberos SPN "
                             "(auto-resolved via reverse DNS if omitted)")
    parser.add_argument("-o", "--output", default=None,
                        help="Output directory [default: ./ldapdomaindump_output]")
    parser.add_argument("--ldaps", action="store_true",
                        help="Force LDAPS (port 636)")
    parser.add_argument("-k", "--kerberos", action="store_true",
                        help="Force Kerberos auth — bypasses signing and channel binding")
    parser.add_argument("--ccache", default=None,
                        help="Path to an existing Kerberos ccache file")

    args = parser.parse_args()

    if not args.password and not args.hashes and not args.kerberos and not args.ccache:
        if not os.environ.get("KRB5CCNAME"):
            parser.error("Provide -p PASSWORD, -H HASHES, -k (Kerberos), or --ccache.")

    output_dir = args.output or os.path.join(os.getcwd(), "ldapdomaindump_output")
    check_write_access(output_dir)

    # ── Explicit Kerberos or ccache ───────────────────────────────────────────
    if args.kerberos or args.ccache:
        dc_host = args.dc_host or _resolve_dc_host(args.dc, args.domain)
        _dump_kerberos(args.domain, args.username, args.password, args.hashes,
                       args.dc, dc_host, output_dir, ccache=args.ccache)
        return

    # ── Hashes provided → impacket path (ldapdomaindump can't pass-the-hash) ─
    if args.hashes:
        success, err = _dump_ntlm_impacket(
            args.domain, args.username, args.password, args.hashes,
            args.dc, output_dir)
        if success:
            return
        if err == "impacket not installed":
            print("[-] impacket not installed: pip3 install impacket", file=sys.stderr)
            sys.exit(1)
        print(f"[*] NTLM bind failed ({err}), auto-escalating to Kerberos...")
        _auto_kerberos(args.domain, args.username, args.password, args.hashes,
                       args.dc, args.dc_host, output_dir)
        return

    # ── Password path: ldapdomaindump → LDAPS → Kerberos (auto) ─────────────
    signing_blocked = False
    success, err = _ldapdomaindump_subprocess(
        args.domain, args.username, args.password, args.dc, output_dir,
        ldaps=args.ldaps)

    if not success and err == "signing" and not args.ldaps:
        signing_blocked = True
        print("[*] DC enforces LDAP signing / channel binding.")
        print("[*] Retrying over LDAPS (port 636)...")
        success, err = _ldapdomaindump_subprocess(
            args.domain, args.username, args.password, args.dc, output_dir,
            ldaps=True)

    if success:
        process_output_files(output_dir)
        return

    if signing_blocked:
        print(f"[-] LDAPS also failed: {err}")
        print("[*] Auto-escalating to Kerberos authentication...")
        _auto_kerberos(args.domain, args.username, args.password, args.hashes,
                       args.dc, args.dc_host, output_dir)
        return

    print(f"[-] ldapdomaindump failed: {err}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
