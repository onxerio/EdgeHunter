# EdgeHunter - Scanner Module v1.2
# Network scanning, banner grabbing and device fingerprinting

import socket
import threading
import requests
import urllib3
import re
from data.kenya_devices import KENYA_DEVICES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Scanner:
    def __init__(self):
        self.open_ports = []
        self.identified_devices = []
        self.banners = {}
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

    def grab_banner(self, ip, port, timeout=3):
        """Grab detailed banner from service"""
        banner_info = {
            "raw": "",
            "server": "",
            "title": "",
            "model": "",
            "firmware": "",
            "vendor": ""
        }

        try:
            if port in [80, 8080, 8000]:
                url = f"http://{ip}:{port}"
                r = requests.get(
                    url,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True
                )
                banner_info["raw"] = r.text[:500]
                banner_info["server"] = r.headers.get("Server", "")

                # Extract title
                title_match = re.search(
                    r"<title>(.*?)</title>",
                    r.text, re.IGNORECASE
                )
                if title_match:
                    banner_info["title"] = title_match.group(1)

                # Extract model info
                for pattern in [
                    r"model[\"'\s:]+([A-Za-z0-9\-]+)",
                    r"firmware[\"'\s:]+([A-Za-z0-9\.\-]+)",
                    r"version[\"'\s:]+([A-Za-z0-9\.\-]+)"
                ]:
                    match = re.search(pattern, r.text, re.IGNORECASE)
                    if match:
                        banner_info["model"] = match.group(1)
                        break

            elif port in [443, 8443]:
                url = f"https://{ip}:{port}"
                r = requests.get(
                    url,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True
                )
                banner_info["raw"] = r.text[:500]
                banner_info["server"] = r.headers.get("Server", "")

                title_match = re.search(
                    r"<title>(.*?)</title>",
                    r.text, re.IGNORECASE
                )
                if title_match:
                    banner_info["title"] = title_match.group(1)

            elif port == 22:
                sock = socket.socket()
                sock.settimeout(timeout)
                sock.connect((ip, port))
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                sock.close()
                banner_info["raw"] = banner
                banner_info["server"] = banner.strip()

            elif port == 23:
                sock = socket.socket()
                sock.settimeout(timeout)
                sock.connect((ip, port))
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                sock.close()
                banner_info["raw"] = banner

            elif port == 8291:
                # Mikrotik Winbox port
                banner_info["vendor"] = "MikroTik"
                banner_info["server"] = "MikroTik Winbox"

        except Exception as e:
            pass

        return banner_info

    def grab_all_banners(self, ip, open_ports):
        """Grab banners from all open ports"""
        print(f"\n[*] Grabbing banners from {ip}...")
        self.banners = {}

        for port in open_ports:
            print(f"[*] Grabbing banner from port {port}...")
            banner = self.grab_banner(ip, port)
            self.banners[port] = banner

            if banner["server"]:
                print(f"[+] Port {port} — Server: {banner['server']}")
            if banner["title"]:
                print(f"[+] Port {port} — Title: {banner['title']}")
            if banner["model"]:
                print(f"[+] Port {port} — Model: {banner['model']}")

        return self.banners

    def identify_device_by_banner(self, banners):
        """Identify device using banner information"""
        
        # Banner fingerprints for each device
        FINGERPRINTS = {
            "mikrotik": [
                "mikrotik", "routeros", "winbox",
                "rb750", "rb951", "ccr"
            ],
            "hikvision": [
                "hikvision", "dvr", "nvr", "ipc",
                "webcomponents", "hikam"
            ],
            "huawei": [
                "huawei", "hg532", "hg8", "echolife",
                "smartax"
            ],
            "cisco": [
                "cisco", "ios", "catalyst",
                "aironet", "linksys"
            ],
            "dahua": [
                "dahua", "dss", "ipc-hfw",
                "nvr", "xvr"
            ],
            "nokia": [
                "nokia", "gpon", "bell",
                "alcatel", "dsldevice"
            ]
        }

        scores = {device: 0 for device in FINGERPRINTS}

        for port, banner in banners.items():
            # Combine all banner text
            banner_text = " ".join([
                banner.get("raw", ""),
                banner.get("server", ""),
                banner.get("title", ""),
                banner.get("model", ""),
                banner.get("vendor", "")
            ]).lower()

            # Score each device type
            for device, keywords in FINGERPRINTS.items():
                for keyword in keywords:
                    if keyword in banner_text:
                        scores[device] += 1

        # Find best match
        best_match = max(scores, key=scores.get)
        best_score = scores[best_match]

        if best_score > 0:
            confidence = min(100, best_score * 25)
            return best_match, confidence
        
        return None, 0

    def identify_device(self, ip, open_ports):
        """Identify device type based on ports AND banners"""
        
        # First grab banners
        banners = self.grab_all_banners(ip, open_ports)

        # Try banner-based identification first
        device_type, confidence = self.identify_device_by_banner(banners)

        if device_type and confidence > 50:
            print(f"\n[+] Device identified by banner: {device_type}")
            print(f"[+] Confidence: {confidence}%")

            result = {
                "device_type": device_type,
                "name": KENYA_DEVICES.get(
                    device_type, {}
                ).get("name", device_type),
                "confidence": f"{confidence}%",
                "matching_ports": open_ports,
                "cves": KENYA_DEVICES.get(
                    device_type, {}
                ).get("cves", []),
                "default_creds": KENYA_DEVICES.get(
                    device_type, {}
                ).get("default_creds", []),
                "banners": banners
            }
            return [result]

        # Fall back to port-based identification
        print(f"[*] Falling back to port-based identification...")
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
                    "default_creds": device["default_creds"],
                    "banners": banners
                })

        matches.sort(
            key=lambda x: x["confidence"],
            reverse=True
        )

        if matches:
            best = matches[0]
            print(f"[+] Device identified: {best['name']}")
            print(f"[+] Confidence: {best['confidence']}")
            print(f"[+] Known CVEs: {[c['id'] for c in best['cves']]}")

        return matches

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