# EdgeHunter - Kenya Device Intelligence Database
# Research shows 30,000+ exposed edge devices in Kenya

KENYA_DEVICES = {
    "mikrotik": {
        "name": "MikroTik Router",
        "count_kenya": 19000,
        "winbox_exposed": 7200,
        "ports": [8291, 80, 443, 22, 23],
        "shodan_query": "country:KE mikrotik",
        "default_creds": [
            ("admin", ""),
            ("admin", "admin"),
            ("admin", "mikrotik"),
        ],
        "cves": [
            {
                "id": "CVE-2018-14847",
                "severity": "CRITICAL",
                "description": "Winbox authentication bypass - credential extraction",
                "affected": "RouterOS < 6.42.1"
            }
        ]
    },
    "hikvision": {
        "name": "Hikvision IP Camera",
        "count_kenya": 5500,
        "ports": [80, 443, 554, 8000, 8080],
        "shodan_query": "country:KE Hikvision",
        "default_creds": [
            ("admin", "12345"),
            ("admin", "admin"),
            ("admin", "123456"),
        ],
        "cves": [
            {
                "id": "CVE-2021-36260",
                "severity": "CRITICAL",
                "description": "Unauthenticated RCE via web server",
                "affected": "Multiple firmware versions"
            }
        ]
    },
    "huawei": {
        "name": "Huawei Router/Switch",
        "count_kenya": 3520,
        "ports": [80, 443, 22, 23, 37215],
        "shodan_query": "country:KE huawei",
        "default_creds": [
            ("admin", "admin"),
            ("root", "admin"),
            ("admin", "huawei"),
        ],
        "cves": [
            {
                "id": "CVE-2017-17215",
                "severity": "HIGH",
                "description": "Remote code execution via UPnP",
                "affected": "HG532 series"
            }
        ]
    },
    "cisco": {
        "name": "Cisco Network Device",
        "count_kenya": 1680,
        "ports": [80, 443, 22, 23, 161],
        "shodan_query": "country:KE cisco",
        "default_creds": [
            ("admin", "admin"),
            ("cisco", "cisco"),
            ("admin", "password"),
        ],
        "cves": [
            {
                "id": "CVE-2023-20198",
                "severity": "CRITICAL",
                "description": "Privilege escalation via web UI",
                "affected": "IOS XE Web UI"
            }
        ]
    },
    "dahua": {
        "name": "Dahua IP Camera",
        "count_kenya": 156,
        "ports": [80, 443, 554, 37777],
        "shodan_query": "country:KE dahua",
        "default_creds": [
            ("admin", "admin"),
            ("admin", ""),
            ("666666", "666666"),
        ],
        "cves": [
            {
                "id": "CVE-2021-33044",
                "severity": "CRITICAL",
                "description": "Authentication bypass",
                "affected": "Multiple models"
            }
        ]
    }
}

# Risk scoring
RISK_LEVELS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 5,
    "LOW": 2
}

def get_total_exposed():
    return sum(d["count_kenya"] for d in KENYA_DEVICES.values())

def get_device_by_port(port):
    matches = []
    for name, device in KENYA_DEVICES.items():
        if port in device["ports"]:
            matches.append(name)
    return matches