# EdgeHunter - Recon Module
# Shodan-powered edge device discovery

import shodan
import json
from data.kenya_devices import KENYA_DEVICES

class Recon:
    def __init__(self, api_key):
        self.api = shodan.Shodan(api_key)
        self.results = {}

    def search_device(self, device_type, limit=10):
        """Search Shodan for specific device type in Kenya"""
        if device_type not in KENYA_DEVICES:
            print(f"Unknown device type: {device_type}")
            return []

        device = KENYA_DEVICES[device_type]
        query = device["shodan_query"]

        print(f"\n[*] Searching Shodan for {device['name']} in Kenya...")
        print(f"[*] Query: {query}")

        try:
            results = self.api.search(query, limit=limit)
            found = []

            for result in results["matches"]:
                target = {
                    "ip": result["ip_str"],
                    "port": result["port"],
                    "org": result.get("org", "Unknown"),
                    "city": result.get("location", {}).get("city", "Unknown"),
                    "hostnames": result.get("hostnames", []),
                    "os": result.get("os", "Unknown"),
                    "banner": result.get("data", "")[:200],
                    "device_type": device_type,
                    "cves": device["cves"]
                }
                found.append(target)
                print(f"[+] Found: {target['ip']}:{target['port']} | {target['org']} | {target['city']}")

            self.results[device_type] = found
            print(f"\n[*] Total found: {len(found)}")
            return found

        except shodan.APIError as e:
            print(f"[-] Shodan API Error: {e}")
            return []

    def search_all(self, limit=5):
        """Search for all Kenya device types"""
        print("\n" + "="*50)
        print("   EDGEHUNTER - KENYA RECON")
        print("="*50)

        all_results = {}
        for device_type in KENYA_DEVICES:
            results = self.search_device(device_type, limit)
            all_results[device_type] = results

        return all_results

    def search_target(self, target):
        """Search Shodan for specific IP or domain"""
        print(f"\n[*] Looking up target: {target}")
        try:
            result = self.api.host(target)
            print(f"[+] IP: {result['ip_str']}")
            print(f"[+] Org: {result.get('org', 'Unknown')}")
            print(f"[+] OS: {result.get('os', 'Unknown')}")
            print(f"[+] Ports: {[s['port'] for s in result['data']]}")
            return result
        except shodan.APIError as e:
            print(f"[-] Error: {e}")
            return None

    def save_results(self, filename="recon_results.json"):
        """Save results to JSON file"""
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=4)
        print(f"\n[+] Results saved to {filename}")