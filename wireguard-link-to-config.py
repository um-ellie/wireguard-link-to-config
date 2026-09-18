#!/usr/bin/env python3
"""
Wireguard link to Config
Converts wireguard:// and wg:// links into standard WireGuard .conf files.
Cross-platform: Windows and Linux.
"""

import argparse
import os
import sys
import urllib.parse
from pathlib import Path

__version__ = "1.1.0"


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


def clean_base64_key(key: str) -> str:
    """Ensure spaces caused by URL decoding are restored to '+' in base64 keys."""
    return key.strip().replace(" ", "+")


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

    remainder = link[scheme_len:]

    # Extract fragment (#name)
    fragment = ""
    if "#" in remainder:
        remainder, raw_fragment = remainder.split("#", 1)
        fragment = urllib.parse.unquote(raw_fragment).strip()

    # Extract query (?params)
    query_str = ""
    if "?" in remainder:
        remainder, query_str = remainder.split("?", 1)

    params = urllib.parse.parse_qs(query_str, keep_blank_values=True)

    # Authority: [userinfo@]endpoint[/]
    authority = remainder.strip("/")

    private_key = ""
    endpoint = ""

    if "@" in authority:
        raw_userinfo, endpoint = authority.rsplit("@", 1)
        private_key = clean_base64_key(urllib.parse.unquote(raw_userinfo))
    else:
        endpoint = authority

    endpoint = endpoint.strip("/")

    # Fallback to query parameters if not found in authority
    if not private_key:
        private_key = clean_base64_key(get_first_param(params, "privatekey", "private_key", "privkey"))

    if not endpoint:
        endpoint = get_first_param(params, "endpoint", "host").strip("/")

    public_key = clean_base64_key(get_first_param(params, "publickey", "public_key", "pubkey"))

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
        preshared_key = clean_base64_key(preshared_key)

    keepalive = get_first_param(params, "persistent_keepalive", "persistentkeepalive", "keepalive")

    return {
        "name": fragment,
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


def parse_batch_links(content: str) -> tuple[list[dict], list[str]]:
    """
    Parse multiple WireGuard links from a text file content.
    Returns (list_of_configs, list_of_errors).
    """
    configs = []
    errors = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, 1):
        line = line.strip().strip('"\'')
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        lower = line.lower()
        if not lower.startswith("wireguard://") and not lower.startswith("wg://"):
            continue

        try:
            cfg = parse_wireguard_link(line)
            configs.append(cfg)
        except Exception as e:
            errors.append(f"Line {idx}: {e}")

    return configs, errors


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


def save_single_file(
    output_file: Path,
    conf_content: str,
    chmod_600: bool,
    overwrite: bool,
    is_interactive: bool,
) -> bool:
    """Write configuration file to disk with the desired permissions."""
    if output_file.exists() and not overwrite:
        if is_interactive:
            ans = prompt_user(f"File '{output_file.name}' already exists. Overwrite? [y/N]", "n").lower()
            if ans not in ("y", "yes"):
                print(f"Skipped '{output_file.name}'.")
                return False
        else:
            raise FileExistsError(f"File '{output_file}' already exists. Use -y / --yes to overwrite.")

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(conf_content)

    if os.name != "nt" and chmod_600:
        try:
            os.chmod(output_file, 0o600)
        except OSError:
            pass

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Convert WireGuard URI links to .conf files (Windows & Linux compatible)."
    )
    parser.add_argument("-l", "--link", help="WireGuard link (wireguard:// or wg://)")
    parser.add_argument("-f", "--file", help="Path to text file containing WireGuard link(s)")
    parser.add_argument("-n", "--name", help="Configuration name (e.g. wg0 or Server1, for single link)")
    parser.add_argument("-o", "--output", help="Output directory path")
    parser.add_argument("-y", "--yes", action="store_true", help="Overwrite existing files without prompting")
    parser.add_argument("-p", "--chmod-600", action="store_true", help="Set restrictive file permissions (chmod 600)")
    parser.add_argument("--stdout", action="store_true", help="Print configuration to stdout instead of saving")
    parser.add_argument("-v", "--version", action="version", version=f"Wireguard link to Config v{__version__}")

    args = parser.parse_args()
    is_interactive = not args.link and not args.file

    # On Windows interactive session, keep console window open on exit
    def exit_handler():
        if is_interactive and os.name == "nt":
            input("\nPress Enter to exit...")

    try:
        configs = []
        is_batch = False

        if is_interactive:
            print("========================================")
            print(f"      Wireguard link to Config v{__version__}")
            print("========================================\n")

            while True:
                raw_input = prompt_user("Enter WireGuard link or file path (.txt)")
                if raw_input:
                    break
                print("Error: Input cannot be empty. Please try again.\n")

            input_path = Path(raw_input).expanduser()
            if input_path.is_file():
                content = input_path.read_text(encoding="utf-8")
                cfgs, errors = parse_batch_links(content)
                for err in errors:
                    print(f"Warning: {err}", file=sys.stderr)
                if not cfgs:
                    raise ValueError(f"No valid WireGuard links found in '{input_path}'.")
                configs = cfgs
                is_batch = True
                print(f"Loaded {len(configs)} link(s) from '{input_path}'.")
            else:
                configs = [parse_wireguard_link(raw_input)]
                is_batch = False
        elif args.file:
            input_path = Path(args.file).expanduser()
            if not input_path.is_file():
                raise FileNotFoundError(f"File not found: '{args.file}'")
            content = input_path.read_text(encoding="utf-8")
            cfgs, errors = parse_batch_links(content)
            for err in errors:
                print(f"Warning: {err}", file=sys.stderr)
            if not cfgs:
                raise ValueError(f"No valid WireGuard links found in '{input_path}'.")
            configs = cfgs
            is_batch = len(configs) > 1
        else:
            configs = [parse_wireguard_link(args.link)]
            is_batch = False

        # Output to stdout if requested
        if args.stdout:
            for idx, cfg in enumerate(configs):
                if len(configs) > 1:
                    cfg_name = cfg["name"] or f"wg{idx}"
                    print(f"# Configuration: {cfg_name}.conf")
                print(generate_conf_content(cfg), end="")
                if idx < len(configs) - 1:
                    print("\n---")
            return

        # Name handling for single link
        if not is_batch and len(configs) == 1:
            if args.name:
                configs[0]["name"] = args.name
            elif is_interactive:
                default_name = configs[0]["name"] or "wg0"
                configs[0]["name"] = prompt_user("Enter configuration name", default_name)
            elif not configs[0]["name"]:
                configs[0]["name"] = "wg0"

        # Determine output directory
        if args.output:
            output_dir = Path(args.output).expanduser()
        elif is_interactive:
            default_dir = str(get_default_output_dir())
            entered_dir = prompt_user("Enter output directory", default_dir)
            output_dir = Path(entered_dir).expanduser()
        else:
            output_dir = get_default_output_dir()

        # Permission prompt in interactive mode on non-Windows
        apply_chmod_600 = args.chmod_600
        if is_interactive and os.name != "nt":
            ans = prompt_user("Set restrictive file permissions (chmod 600 - private key protected)? [y/N]", "n").lower()
            apply_chmod_600 = ans in ("y", "yes")

        used_names: dict[str, int] = {}
        success_count = 0
        print()

        for idx, cfg in enumerate(configs):
            raw_name = cfg["name"] or f"wg{idx}"
            sanitized = sanitize_config_name(raw_name)

            if sanitized in used_names:
                used_names[sanitized] += 1
                final_name = f"{sanitized}_{used_names[sanitized]}"
            else:
                used_names[sanitized] = 0
                final_name = sanitized

            output_file = output_dir / f"{final_name}.conf"
            conf_content = generate_conf_content(cfg)

            saved = save_single_file(
                output_file=output_file,
                conf_content=conf_content,
                chmod_600=apply_chmod_600,
                overwrite=args.yes,
                is_interactive=is_interactive,
            )

            if saved:
                success_count += 1
                if is_batch or len(configs) > 1:
                    print(f"[✔] Saved: {final_name}.conf -> {output_file.resolve()}")
                else:
                    print("[✔] Success: WireGuard configuration created successfully.")
                    print(f"Name      : {final_name}")
                    print(f"Path      : {output_file.resolve()}")
                    if cfg.get("mtu"):
                        print(f"MTU       : {cfg['mtu']}")
                    if cfg.get("persistent_keepalive"):
                        print(f"Keepalive : {cfg['persistent_keepalive']}s")
                    if os.name != "nt":
                        perms_str = "600 (Private)" if apply_chmod_600 else "Default (Standard)"
                        print(f"Permission: {perms_str}")

        if is_batch or len(configs) > 1:
            print(f"\n[✔] Batch conversion complete: {success_count} of {len(configs)} configuration(s) saved in '{output_dir.resolve()}'.")
            if os.name != "nt":
                perms_str = "600 (Private)" if apply_chmod_600 else "Default (Standard)"
                print(f"Permission: {perms_str}")

    except Exception as err:
        print(f"\nError: {err}", file=sys.stderr)
        sys.exit(1)
    finally:
        exit_handler()


if __name__ == "__main__":
    main()
