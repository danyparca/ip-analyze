# ip-analyze
🐍 Simple IP OSINT &amp; Analysis Tool by Dany La Parca
IP ANALIZE - Simple IP Analysis Tool
Version 1.1 by Dany La Parca

Simple IP Open Source Intelligence tool for gathering information about IP addresses.

Features
Robust IP Validation - Validates IPv4 addresses (each octet 0-255)
Private IP Detection - Warns when querying private/local IPs
Retry Mechanism - Automatic retry for transient network failures
API Token Support - Higher rate limits with ipinfo.io token
JSON Export - Save results to timestamped JSON files
Colorized Output - Clean, formatted terminal display
Requirements
Python 3.8+
requests module
Installation
pip install requests
Usage
Basic Usage
bash

python ip_analize.py
With API Token (Optional)
For higher rate limits:

bash

# Linux/macOS
export IPINFO_TOKEN=your_token_here
python ip_analize.py

# Windows
set IPINFO_TOKEN=your_token_here
python ip_analize.py
Get your free API token at: https://ipinfo.io/signup

Example Output
text

███╗   ███╗██╗   ██╗ █████╗ ███████╗ ██████╗██████╗ 
████╗ ████║██║   ██║██╔══██╗╚══███╔╝██╔════╝██╔══██╗
██╔████╔██║██║   ██║███████║  ███╔╝ ██║     ██████╔╝
██║╚██╔╝██║╚██╗ ██╔╝██╔══██║ ███╔╝  ██║     ██╔══██╗
██║ ╚═╝ ██║ ╚████╔╝ ██║  ██║███████╗╚██████╗██║  ██║
╚═╝     ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
 Simple IP ANALIZE by Dany La Parca v1.1 

 Enter the Target IP : 8.8.8.8

+----------------------------------------+
|          IP INFORMATION                |
+----------------------------------------+
|  IP Address    : 8.8.8.8               |
|  Hostname      : dns.google            |
|  Country       : US                    |
|  Organization  : AS15169 Google LLC    |
+----------------------------------------+
Exit Codes
Code
Description
0	Success
1	Invalid IP address
2	API error
3	Network error
4	Rate limited
130	Interrupted by user (Ctrl+C)

Rate Limits
Plan
Requests/Month
Free (no token)	50,000
Free (with token)	100,000

Author
Dany La Parca - Version 1.1

Disclaimer
This tool is for educational and authorized use only.

python ip_analize.py
