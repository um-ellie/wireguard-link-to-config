#!/usr/bin/env python3
"""
WireGuard Configuration Generator
Converts wireguard:// and wg:// links into standard WireGuard .conf files.
Cross-platform: Windows and Linux.
"""

import argparse
import os
import sys
import urllib.parse
from pathlib import Path


def sanitize_config_name(name: str) -> str:
    """Clean and validate the configuration file name."""
    name = name.strip()
    if name.lower().endswith(".conf"):
        name = name[:-5]
    name = name.strip()

    if not name:
        raise ValueError("Configuration name cannot be empty.")

    invalid_chars = set('/\\:*?"<>|')
    if any(char in invalid_chars for char in name) or name in (".", ".."):
        raise ValueError(f"Invalid characters in configuration name: '{name}'")

    return name


def get_first_param(params: dict, *keys: str) -> str:
    """Retrieve the first non-empty value from a query params dictionary."""
    for key in keys:
        vals = params.get(key, [])
        if vals and vals[0].strip():
            return vals[0].strip()
    return ""


def parse_wireguard_link(link: str) -> dict:
    """
    Parse a WireGuard URI (wireguard:// or wg://) and return a dictionary with configuration fields.
    """
    link = link.strip().strip('"\'')
    if not link:
        raise ValueError("No configuration link provided.")

    lower_link = link.lower()
    if lower_link.startswith("wireguard://"):
        scheme_len = len("wireguard://")
    elif lower_link.startswith("wg://"):
        scheme_len = len("wg://")
    else:
        raise ValueError("Invalid link format. Must start with 'wireguard://' or 'wg://'.")

    # Replace custom scheme with https:// for standard URI parsing
    normalized_url = "https://" + link[scheme_len:]
    parsed = urllib.parse.urlparse(normalized_url)
    params = urllib.parse.parse_qs(parsed.query)

    # Extract private key (from userinfo or query)
    private_key = urllib.parse.unquote(parsed.username or "")
    if not private_key:
        private_key = get_first_param(params, "privatekey", "private_key", "privkey")
    private_key = urllib.parse.unquote(private_key)

    # Extract endpoint (from host or query)
    endpoint = parsed.netloc.split("@")[-1]
    if not endpoint:
        endpoint = get_first_param(params, "endpoint", "host")

    # Extract public key
    public_key = get_first_param(params, "publickey", "public_key", "pubkey")
    public_key = urllib.parse.unquote(public_key)

    if not private_key:
        raise ValueError("Missing required field: PrivateKey.")
    if not public_key:
        raise ValueError("Missing required field: PublicKey.")
    if not endpoint:
        raise ValueError("Missing required field: Endpoint.")

    # Address and DNS
    address = get_first_param(params, "address", "ip") or "10.0.0.2/32"
    dns = get_first_param(params, "dns") or "1.1.1.1"

    # AllowedIPs
    allowed_ips = get_first_param(params, "allowed_ips", "allowedips") or "0.0.0.0/0, ::/0"

    # MTU: ONLY included if explicitly specified in the link
    mtu = get_first_param(params, "mtu")

    # Optional fields
    preshared_key = get_first_param(params, "presharedkey", "preshared_key", "psk")
    if preshared_key:
        preshared_key = urllib.parse.unquote(preshared_key)

    keepalive = get_first_param(params, "persistent_keepalive", "persistentkeepalive", "keepalive")

    # Extract config name from URL fragment (e.g. #Germany)
    fragment_name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ""

    return {
        "name": fragment_name,
        "private_key": private_key,
        "public_key": public_key,
        "endpoint": endpoint,
        "address": address,
        "dns": dns,
        "allowed_ips": allowed_ips,
        "mtu": mtu,
        "preshared_key": preshared_key,
        "persistent_keepalive": keepalive,
    }


def generate_conf_content(config_data: dict) -> str:
    """Generate standard WireGuard INI config format."""
    lines = [
        "[Interface]",
        f"PrivateKey = {config_data['private_key']}",
        f"Address = {config_data['address']}",
    ]

    if config_data.get("dns"):
        lines.append(f"DNS = {config_data['dns']}")

    # Only add MTU if provided
    if config_data.get("mtu"):
        lines.append(f"MTU = {config_data['mtu']}")

    lines.extend([
        "",
        "[Peer]",
        f"PublicKey = {config_data['public_key']}",
        f"Endpoint = {config_data['endpoint']}",
        f"AllowedIPs = {config_data['allowed_ips']}",
    ])

    if config_data.get("preshared_key"):
        lines.append(f"PresharedKey = {config_data['preshared_key']}")

    if config_data.get("persistent_keepalive"):
        lines.append(f"PersistentKeepalive = {config_data['persistent_keepalive']}")

    return "\n".join(lines) + "\n"


def get_default_output_dir() -> Path:
    """Return an appropriate default output directory for the current OS."""
    if os.name == "nt":
        return Path(".")

    # On Linux/macOS, if root and /etc/wireguard exists, suggest it
    try:
        if os.geteuid() == 0 and Path("/etc/wireguard").is_dir():
            return Path("/etc/wireguard")
    except AttributeError:
        pass

    return Path(".")


def prompt_user(message: str, default: str = "") -> str:
    """Prompt user with optional default value."""
    if default:
        val = input(f"{message} [{default}]: ").strip()
        return val if val else default
    return input(f"{message}: ").strip()


def main():
    parser = argparse.ArgumentParser(
        description="Convert WireGuard URI links to .conf files (Windows & Linux compatible)."
    )
    parser.add_argument("-l", "--link", help="WireGuard link (wireguard:// or wg://)")
    parser.add_argument("-n", "--name", help="Configuration name (e.g. wg0 or Server1)")
    parser.add_argument("-o", "--output", help="Output directory path")
    parser.add_argument("-y", "--yes", action="store_true", help="Overwrite existing files without prompting")
    parser.add_argument("--stdout", action="store_true", help="Print configuration to stdout instead of saving")

    args = parser.parse_args()
    is_interactive = not args.link

    # On Windows interactive session, keep console window open on exit
    def exit_handler():
        if is_interactive and os.name == "nt":
            input("\nPress Enter to exit...")

    try:
        if is_interactive:
            print("========================================")
            print("   WireGuard Configuration Generator    ")
            print("========================================\n")

            while True:
                link = prompt_user("Enter WireGuard config link")
                if link:
                    break
                print("Error: Configuration link cannot be empty. Please try again.\n")
        else:
            link = args.link

        # Parse config link
        config_data = parse_wireguard_link(link)

        # Determine config name
        config_name = args.name
        if not config_name:
            if is_interactive:
                default_name = config_data["name"] or "wg0"
                config_name = prompt_user("Enter configuration name", default_name)
            else:
                config_name = config_data["name"] or "wg0"

        config_name = sanitize_config_name(config_name)

        conf_content = generate_conf_content(config_data)

        if args.stdout:
            print(conf_content, end="")
            return

        # Determine output directory
        if args.output:
            output_dir = Path(args.output).expanduser()
        elif is_interactive:
            default_dir = str(get_default_output_dir())
            entered_dir = prompt_user("Enter output directory", default_dir)
            output_dir = Path(entered_dir).expanduser()
        else:
            output_dir = get_default_output_dir()

        output_file = output_dir / f"{config_name}.conf"

        # Check existing file
        if output_file.exists() and not args.yes:
            if is_interactive:
                ans = prompt_user(f"File '{output_file}' already exists. Overwrite? [y/N]", "n").lower()
                if ans not in ("y", "yes"):
                    print("Operation cancelled.")
                    return
            else:
                print(f"Error: File '{output_file}' already exists. Use -y / --yes to overwrite.", file=sys.stderr)
                sys.exit(1)

        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)

        # Write configuration
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(conf_content)

        # Secure permissions on POSIX systems (skip on Windows)
        if os.name != "nt":
            try:
                os.chmod(output_file, 0o600)
            except Exception:
                pass

        print("\n[✔] Success: WireGuard configuration created successfully.")
        print(f"Name      : {config_name}")
        print(f"Path      : {output_file.resolve()}")
        if config_data.get("mtu"):
            print(f"MTU       : {config_data['mtu']}")
        if config_data.get("persistent_keepalive"):
            print(f"Keepalive : {config_data['persistent_keepalive']}s")
        if os.name != "nt":
            print("Permission: 600 (Private)")

    except Exception as err:
        print(f"\nError: {err}", file=sys.stderr)
        sys.exit(1)
    finally:
        exit_handler()


if __name__ == "__main__":
    main()
