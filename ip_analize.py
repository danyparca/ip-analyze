#!/usr/bin/env python3
"""
IP ANALIZE - Simple IP Analysis Tool
Version 1.1 by Dany La Parca

Requirements: requests
"""

import os
import re
import sys
import json
import requests
from datetime import datetime
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum


class ExitCode(Enum):
    """Exit codes for the script."""
    SUCCESS = 0
    INVALID_IP = 1
    API_ERROR = 2
    NETWORK_ERROR = 3
    RATE_LIMITED = 4


@dataclass
class IPInfo:
    """Data class to store IP information."""
    ip: str
    hostname: Optional[str] = None
    anycast: Optional[bool] = None
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    location: Optional[str] = None
    org: Optional[str] = None
    postal: Optional[str] = None
    timezone: Optional[str] = None
    asn: Optional[str] = None
    company: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IPInfo':
        """Create IPInfo instance from API response dictionary."""
        return cls(
            ip=data.get('ip', 'N/A'),
            hostname=data.get('hostname'),
            anycast=data.get('anycast'),
            city=data.get('city'),
            region=data.get('region'),
            country=data.get('country'),
            location=data.get('loc'),
            org=data.get('org'),
            postal=data.get('postal'),
            timezone=data.get('timezone'),
            asn=data.get('asn', {}).get('asn') if isinstance(data.get('asn'), dict) else None,
            company=data.get('company', {}).get('name') if isinstance(data.get('company'), dict) else None
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON export."""
        return {
            'ip': self.ip,
            'hostname': self.hostname,
            'anycast': self.anycast,
            'city': self.city,
            'region': self.region,
            'country': self.country,
            'location': self.location,
            'organization': self.org,
            'postal': self.postal,
            'timezone': self.timezone,
            'asn': self.asn,
            'company': self.company
        }


class IPValidator:
    """Class for IP address validation."""
    
    IPV4_PATTERN = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    
    @classmethod
    def is_valid_ipv4(cls, ip: str) -> bool:
        match = cls.IPV4_PATTERN.match(ip)
        if not match:
            return False
        for octet in match.groups():
            if int(octet) > 255:
                return False
        return True
    
    @classmethod
    def is_private_ip(cls, ip: str) -> bool:
        if not cls.is_valid_ipv4(ip):
            return False
        octets = [int(x) for x in ip.split('.')]
        if octets[0] == 10:
            return True
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        if octets[0] == 192 and octets[1] == 168:
            return True
        if octets[0] == 127:
            return True
        return False


class IPInfoAPI:
    """Class to interact with ipinfo.io API."""
    
    BASE_URL = "https://ipinfo.io"
    
    def __init__(self, token: Optional[str] = None, timeout: int = 10, max_retries: int = 3):
        self.token = token
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'IP-ANALIZE/1.1',
            'Accept': 'application/json'
        })
    
    def _build_url(self, ip: str) -> str:
        url = f"{self.BASE_URL}/{ip}/json"
        if self.token:
            url += f"?token={self.token}"
        return url
    
    def get_ip_info(self, ip: str) -> tuple:
        for attempt in range(self.max_retries):
            try:
                response = self.session.get(self._build_url(ip), timeout=self.timeout)
                if response.status_code == 429:
                    return None, "Rate limited. Consider using an API token."
                if response.status_code == 404:
                    return None, f"IP address '{ip}' not found."
                if response.status_code == 403:
                    return None, "Access forbidden. Invalid API token or rate limit exceeded."
                response.raise_for_status()
                data = response.json()
                if 'error' in data:
                    return None, f"API Error: {data.get('error', {}).get('message', 'Unknown error')}"
                return IPInfo.from_dict(data), None
            except requests.exceptions.Timeout:
                if attempt < self.max_retries - 1:
                    continue
                return None, f"Request timed out after {self.timeout} seconds."
            except requests.exceptions.ConnectionError:
                if attempt < self.max_retries - 1:
                    continue
                return None, "Connection error. Check your internet connection."
            except requests.exceptions.HTTPError as e:
                return None, f"HTTP error: {e}"
            except json.JSONDecodeError:
                return None, "Invalid response from API."
            except requests.exceptions.RequestException as e:
                return None, f"Request failed: {e}"
        return None, "Maximum retries exceeded."


class Display:
    """Class for displaying formatted output."""
    
    COLORS = {
        'reset': '\033[0m', 'red': '\033[91m', 'green': '\033[92m',
        'yellow': '\033[93m', 'blue': '\033[94m', 'magenta': '\033[95m',
        'cyan': '\033[96m', 'white': '\033[97m', 'bold': '\033[1m',
        'dim': '\033[2m', 'bg_red': '\033[41m', 'bg_green': '\033[42m',
        'bg_yellow': '\033[43m', 'bg_blue': '\033[44m', 'bg_cyan': '\033[46m',
    }
    
    @classmethod
    def colorize(cls, text: str, color: str) -> str:
        return f"{cls.COLORS.get(color, '')}{text}{cls.COLORS['reset']}"
    
    @classmethod
    def clear_screen(cls) -> None:
        print('\033[2J\033[H', end='')
    
    @classmethod
    def banner(cls) -> None:
        print(f"""
{cls.colorize('███╗   ███╗██╗   ██╗ █████╗ ███████╗ ██████╗██████╗ ', 'blue')}
{cls.colorize('████╗ ████║██║   ██║██╔══██╗╚══███╔╝██╔════╝██╔══██╗', 'blue')}
{cls.colorize('██╔████╔██║██║   ██║███████║  ███╔╝ ██║     ██████╔╝', 'blue')}
{cls.colorize('██║╚██╔╝██║╚██╗ ██╔╝██╔══██║ ███╔╝  ██║     ██╔══██╗', 'white')}
{cls.colorize('██║ ╚═╝ ██║ ╚████╔╝ ██║  ██║███████╗╚██████╗██║  ██║', 'white')}
{cls.colorize('╚═╝     ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝', 'white')}
{cls.colorize(' Simple IP ANALIZE by Dany La Parca v1.1 ', 'bg_cyan')}
""")
    
    @classmethod
    def error(cls, message: str) -> None:
        print(f"\n{cls.colorize('[ERROR]', 'bg_red')} {message}\n")
    
    @classmethod
    def warning(cls, message: str) -> None:
        print(f"\n{cls.colorize('[WARNING]', 'bg_yellow')} {message}\n")
    
    @classmethod
    def success(cls, message: str) -> None:
        print(f"\n{cls.colorize('[SUCCESS]', 'bg_green')} {message}\n")
    
    @classmethod
    def info_box(cls, title: str, data: Dict[str, Any], highlight_keys: List[str] = None) -> None:
        highlight_keys = highlight_keys or ['ip', 'hostname', 'country', 'org']
        key_width = max(len(str(k)) for k in data.keys()) + 2
        val_width = max(len(str(v)) if v else 4 for v in data.values()) + 2
        separator = '+' + '-' * (key_width + val_width + 3) + '+'
        print(f"\n{cls.colorize(separator, 'cyan')}")
        print(f"{cls.colorize('|', 'cyan')} {cls.colorize(title.center(key_width + val_width + 1), 'bold')} {cls.colorize('|', 'cyan')}")
        print(f"{cls.colorize(separator, 'cyan')}")
        for key, value in data.items():
            key_str = str(key).replace('_', ' ').title()
            val_str = str(value) if value is not None else 'N/A'
            if key in highlight_keys:
                key_display = cls.colorize(f"  {key_str:<{key_width}}", 'green')
            else:
                key_display = cls.colorize(f"  {key_str:<{key_width}}", 'white')
            print(f"{cls.colorize('|', 'cyan')} {key_display}: {val_str:<{val_width}} {cls.colorize('|', 'cyan')}")
        print(f"{cls.colorize(separator, 'cyan')}\n")
    
    @classmethod
    def display_ip_info(cls, ip_info: IPInfo) -> None:
        data = {
            'IP Address': ip_info.ip, 'Hostname': ip_info.hostname,
            'Anycast': 'Yes' if ip_info.anycast else 'No', 'City': ip_info.city,
            'Region': ip_info.region, 'Country': ip_info.country,
            'Location': ip_info.location, 'Organization': ip_info.org,
            'ASN': ip_info.asn, 'Company': ip_info.company,
            'Postal Code': ip_info.postal, 'Timezone': ip_info.timezone,
        }
        filtered_data = {k: v for k, v in data.items() if v is not None}
        cls.info_box('IP INFORMATION', filtered_data, ['IP Address', 'Country', 'Organization'])
    
    @classmethod
    def prompt(cls, message: str, color: str = 'bg_yellow') -> str:
        prompt_text = cls.colorize(f' {message} ', color)
        return input(f"\n{prompt_text}: ").strip()


class JSONExporter:
    """Class for exporting results to JSON."""
    
    @staticmethod
    def save(ip_info: IPInfo, filename: Optional[str] = None) -> str:
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"ip_{ip_info.ip.replace('.', '_')}_{timestamp}.json"
        data = {'timestamp': datetime.now().isoformat(), 'data': ip_info.to_dict()}
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return filename


def main() -> int:
    """Main function of the script."""
    display = Display()
    display.clear_screen()
    display.banner()
    
    api_token = os.environ.get('IPINFO_TOKEN')
    if api_token:
        display.success("API token found. Higher rate limits enabled.")
    
    api = IPInfoAPI(token=api_token)
    
    while True:
        ip = display.prompt('Enter the Target IP')
        if ip.lower() in ('exit', 'quit', 'q'):
            print("\nGoodbye!\n")
            return ExitCode.SUCCESS
        if not IPValidator.is_valid_ipv4(ip):
            display.error(f"'{ip}' is not a valid IPv4 address.")
            print("Please enter a valid IP (e.g., 8.8.8.8)")
            continue
        if IPValidator.is_private_ip(ip):
            display.warning(f"'{ip}' is a private IP address.")
        break
    
    print(f"\n{display.colorize('Querying ipinfo.io...', 'dim')}")
    ip_info, error = api.get_ip_info(ip)
    
    if error:
        display.error(error)
        return ExitCode.API_ERROR
    
    if ip_info:
        display.display_ip_info(ip_info)
        save_choice = display.prompt('Save results to JSON? (y/n)', 'bg_blue')
        if save_choice.lower() == 'y':
            try:
                filename = JSONExporter.save(ip_info)
                display.success(f"Results saved to: {filename}")
            except IOError as e:
                display.error(f"Failed to save file: {e}")
    
    return ExitCode.SUCCESS


if __name__ == "__main__":
    try:
        import requests
    except ImportError:
        print("\n[ERROR] The 'requests' module is required.")
        print("Install it with: pip install requests\n")
        sys.exit(1)
    
    if 'IPINFO_TOKEN' not in os.environ:
        print("[TIP] Set IPINFO_TOKEN environment variable for higher rate limits.")
        print("Example: export IPINFO_TOKEN=your_token_here\n")
    
    try:
        exit_code = main()
        sys.exit(exit_code.value)
    except KeyboardInterrupt:
        print(f"\n\nInterrupted by user.\n")
        sys.exit(130)
    except Exception as e:
        Display().error(f"Unexpected error: {e}")
        sys.exit(1)
