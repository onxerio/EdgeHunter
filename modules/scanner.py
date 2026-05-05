# EdgeHunter - Scanner Module
# Network scanning and device fingerprinting

import socket
import threading
import requests
import urllib3
from data.kenya_devices import KENYA_DEVICES

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Scanner:
    def __init__(self):
        self.open_ports = []
        self.identified_devices = []
        self.lock = threading.Lock()

    def check_port(self, ip, port, timeout=2):
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                return True
        except:
            pass
        return False

    def scan_ports(self, ip, ports=None):
        """Scan multiple ports using threads"""
        if ports is None:
            ports = [21, 22, 23, 80, 443, 554, 
                    8000, 8080, 8291, 8443, 37215, 37777]

        print(f"\n[*] Scanning {ip}...")
        self.open_ports = []
        threads = []

        for port in ports:
            t = threading.Thread(
                target=self.check_port,
                args=(ip, port)
            )
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        if self.open_ports:
            print(f"[+] Open ports: {sorted(self.open_ports)}")
        else:
            print(f"[-] No open ports found")

        return sorted(self.open_ports)

    def identify_device(self, ip, open_ports):
        """Identify device type based on open ports"""
        matches = []

        for device_type, device in KENYA_DEVICES.items():
            matching_ports = set(open_ports) & set(device["ports"])
            if matching_ports:
                score = len(matching_ports) / len(device["ports"])
                matches.append({
                    "device_type": device_type,
                    "name": device["name"],
                    "confidence": f"{score*100:.0f}%",
                    "matching_ports": list(matching_ports),
                    "cves": device["cves"],
                    "default_creds": device["default_creds"]
                })

        matches.sort(key=lambda x: x["confidence"], reverse=True)

        if matches:
            best = matches[0]
            print(f"[+] Device identified: {best['name']}")
            print(f"[+] Confidence: {best['confidence']}")
            print(f"[+] Known CVEs: {[c['id'] for c in best['cves']]}")

        return matches

    def grab_banner(self, ip, port, timeout=3):
        """Grab service banner"""
        try:
            if port in [80, 8080, 8000]:
                url = f"http://{ip}:{port}"
                r = requests.get(url, timeout=timeout, verify=False)
                return r.headers.get("Server", "") + " " + r.text[:100]

            elif port in [443, 8443]:
                url = f"https://{ip}:{port}"
                r = requests.get(url, timeout=timeout, verify=False)
                return r.headers.get("Server", "") + " " + r.text[:100]

            else:
                sock = socket.socket()
                sock.settimeout(timeout)
                sock.connect((ip, port))
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                sock.close()
                return banner

        except:
            return ""

    def scan_network(self, network):
        """Scan entire network range"""
        print(f"\n[*] Scanning network: {network}")
        import ipaddress

        net = ipaddress.IPv4Network(network, strict=False)
        alive_hosts = []

        for ip in net.hosts():
            ip_str = str(ip)
            if self.check_port(ip_str, 80, timeout=1) or \
               self.check_port(ip_str, 22, timeout=1):
                alive_hosts.append(ip_str)
                print(f"[+] Host alive: {ip_str}")

        return alive_hosts