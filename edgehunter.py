# EdgeHunter - Edge Device Security Assessment Framework
# By Onserio | Kenya Market Focus
# For authorized security testing only

import argparse
import sys
import os
from modules.recon import Recon
from modules.scanner import Scanner
from modules.exploit import Exploit
from modules.report import Report

BANNER = """
╔═══════════════════════════════════════════════╗
║                                               ║
║   ███████╗██████╗  ██████╗ ███████╗          ║
║   ██╔════╝██╔══██╗██╔════╝ ██╔════╝          ║
║   █████╗  ██║  ██║██║  ███╗█████╗            ║
║   ██╔══╝  ██║  ██║██║   ██║██╔══╝            ║
║   ███████╗██████╔╝╚██████╔╝███████╗          ║
║   ╚══════╝╚═════╝  ╚═════╝ ╚══════╝          ║
║                                               ║
║      ██╗  ██╗██╗   ██╗███╗   ██╗████████╗   ║
║      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝   ║
║      ███████║██║   ██║██╔██╗ ██║   ██║      ║
║      ██╔══██║██║   ██║██║╚██╗██║   ██║      ║
║      ██║  ██║╚██████╔╝██║ ╚████║   ██║      ║
║      ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ║
║                                               ║
║   Edge Device Security Assessment Framework  ║
║   By Onserio | Kenya Market Focus            ║
║   Version 1.0                                ║
╚═══════════════════════════════════════════════╝
"""

def get_api_key():
    """Get Shodan API key from config"""
    try:
        from config import SHODAN_API_KEY
        return SHODAN_API_KEY
    except:
        key = input("[*] Enter Shodan API key: ")
        return key

def mode_recon(args):
    """Recon mode - find exposed devices"""
    api_key = get_api_key()
    recon = Recon(api_key)
    report = Report()

    if args.target:
        # Recon specific target
        result = recon.search_target(args.target)
    else:
        # Recon all Kenya devices
        results = recon.search_all(limit=5)

        # Add to report
        for device_type, devices in results.items():
            for device in devices:
                device["name"] = device_type
                report.add_finding(device)

    # Save results
    recon.save_results()

    # Generate report
    report.generate_terminal_report(
        args.target or "Kenya Edge Devices"
    )
    report.save_report()

def mode_scan(args):
    """Scan mode - scan and identify devices"""
    if not args.target:
        print("[-] Please provide a target: --target <ip>")
        return

    scanner = Scanner()
    report = Report()

    # Scan ports
    open_ports = scanner.scan_ports(args.target)

    if open_ports:
        # Identify device
        matches = scanner.identify_device(args.target, open_ports)

        if matches:
            best_match = matches[0]
            finding = {
                "ip": args.target,
                "name": best_match["name"],
                "port": open_ports[0],
                "org": "Unknown",
                "city": "Unknown",
                "cves": best_match["cves"],
                "device_type": best_match["device_type"]
            }
            report.add_finding(finding)

    # Generate report
    report.generate_terminal_report(args.target)

def mode_exploit(args):
    """Exploit mode - test vulnerabilities"""
    if not args.target:
        print("[-] Please provide a target: --target <ip>")
        return

    exploit = Exploit()
    report = Report()

    # Need device type
    if not args.device:
        print("[-] Please specify device type: --device <type>")
        print("    Available: mikrotik, hikvision, huawei, cisco, dahua")
        return

    # Run exploits
    results = exploit.run_all_exploits(args.target, args.device)

    if results:
        for result in results:
            finding = {
                "ip": args.target,
                "name": args.device,
                "port": result["port"],
                "org": "Unknown",
                "city": "Unknown",
                "cves": [],
                "credentials_found": result
            }
            report.add_finding(finding)

    report.generate_terminal_report(args.target)

def mode_full(args):
    """Full mode - complete attack chain"""
    if not args.target:
        print("[-] Please provide a target: --target <ip/domain>")
        return

    print(f"\n[*] Running full assessment on {args.target}")

    # Step 1 - Recon
    print("\n[PHASE 1] RECONNAISSANCE")
    api_key = get_api_key()
    recon = Recon(api_key)
    target_info = recon.search_target(args.target)

    # Step 2 - Scan
    print("\n[PHASE 2] SCANNING")
    scanner = Scanner()
    open_ports = scanner.scan_ports(args.target)
    matches = scanner.identify_device(args.target, open_ports)

    # Step 3 - Exploit
    report = Report()

    if matches:
        device_type = matches[0]["device_type"]
        print(f"\n[PHASE 3] EXPLOITATION")
        exploit = Exploit()
        results = exploit.run_all_exploits(args.target, device_type)

        finding = {
            "ip": args.target,
            "name": matches[0]["name"],
            "port": open_ports[0] if open_ports else 0,
            "org": "Unknown",
            "city": "Unknown",
            "cves": matches[0]["cves"],
        }

        if results:
            finding["credentials_found"] = results[0]

        report.add_finding(finding)

    # Step 4 - Report
    print("\n[PHASE 4] REPORTING")
    report.generate_terminal_report(args.target)
    report.save_report()

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="EdgeHunter - Edge Device Security Framework"
    )

    parser.add_argument(
        "--mode",
        choices=["recon", "scan", "exploit", "full"],
        required=True,
        help="Operation mode"
    )

    parser.add_argument(
        "--target",
        help="Target IP, domain, or network range"
    )

    parser.add_argument(
        "--device",
        choices=["mikrotik", "hikvision", "huawei", "cisco", "dahua"],
        help="Device type for exploit mode"
    )

    parser.add_argument(
        "--output",
        help="Output file for report"
    )

    args = parser.parse_args()

    # Run selected mode
    if args.mode == "recon":
        mode_recon(args)
    elif args.mode == "scan":
        mode_scan(args)
    elif args.mode == "exploit":
        mode_exploit(args)
    elif args.mode == "full":
        mode_full(args)

if __name__ == "__main__":
    main()