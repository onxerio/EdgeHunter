# EdgeHunter 

Edge Device Security Assessment Framework


## About
EdgeHunter is a security assessment tool 
focused on edge devices commonly found in 
Kenyan organizations including routers, 
IP cameras, and IoT devices.

## Features
- Kenya-specific device database
- Automated CVE matching
- Default credential testing
- Professional report generation

## Usage
```bash
# Scan a target
python edgehunter.py --mode scan --target <ip>

# Full assessment
python edgehunter.py --mode full --target <ip>

# Recon mode
python edgehunter.py --mode recon
```

## Disclaimer
For authorized security testing only.
