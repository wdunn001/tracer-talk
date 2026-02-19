#!/usr/bin/env python3
"""
Tracer Terminal - Generate Clients & Bootstraps
Reads server/config.py and stamps out working client scripts and bootstrap
one-liners with the configured domain and IP baked in.

Usage:
    python generate.py
    python generate.py --domain lab.example.com --ip 1.2.3.4

Generated files go into build/ so the templates in clients/ and bootstrap/
stay clean.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from server.config import DOMAIN_ZONE, SERVER_IP


TEMPLATE_FILES = [
    "clients/chat_client.ps1",
    "clients/chat_client.bat",
    "clients/chat_client.sh",
    "bootstrap/bootstrap_ps.txt",
    "bootstrap/bootstrap_cmd.txt",
    "bootstrap/bootstrap_bash.txt",
]


def render(template: str, domain: str, ip: str) -> str:
    octets = ip.split(".")
    key_csv = ",".join(octets)
    key_space = " ".join(octets)

    out = template
    out = out.replace("{{DOMAIN_ZONE}}", domain)
    out = out.replace("{{SERVER_IP}}", ip)
    out = out.replace("{{KEY_CSV}}", key_csv)
    out = out.replace("{{KEY_SPACE}}", key_space)
    return out


def main():
    parser = argparse.ArgumentParser(description="Generate Tracer Terminal clients and bootstraps")
    parser.add_argument("--domain", "-d", default=DOMAIN_ZONE,
                        help=f"Domain zone (default: {DOMAIN_ZONE} from config.py)")
    parser.add_argument("--ip", "-i", default=SERVER_IP,
                        help=f"Server IP (default: {SERVER_IP} from config.py)")
    parser.add_argument("--out", "-o", default="build",
                        help="Output directory (default: build/)")
    args = parser.parse_args()

    if args.ip == "0.0.0.0":
        print("ERROR: SERVER_IP is still 0.0.0.0 -- configure server/config.py or pass --ip")
        sys.exit(1)
    if args.domain == "lab.yourdomain.com":
        print("ERROR: DOMAIN_ZONE is still the placeholder -- configure server/config.py or pass --domain")
        sys.exit(1)

    root = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(root, args.out)

    print(f"Domain:    {args.domain}")
    print(f"Server IP: {args.ip}")
    print(f"XOR key:   [{', '.join(args.ip.split('.'))}]")
    print(f"Output:    {out_dir}/")
    print()

    for rel_path in TEMPLATE_FILES:
        src = os.path.join(root, rel_path)
        with open(src, "r", encoding="utf-8") as f:
            template = f.read()

        rendered = render(template, args.domain, args.ip)

        dest_dir = os.path.join(out_dir, os.path.dirname(rel_path))
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(out_dir, rel_path)

        with open(dest, "w", encoding="utf-8") as f:
            f.write(rendered)

        size = len(rendered.encode("utf-8"))
        print(f"  {rel_path:40s} -> {dest}  ({size} bytes)")

    print()
    print("Done. Use the files in build/ with the orchestrator:")
    print(f"  sudo python -m server.orchestrator --payload {args.out}/clients/chat_client.ps1 --domain {args.domain} --ip {args.ip}")


if __name__ == "__main__":
    main()
