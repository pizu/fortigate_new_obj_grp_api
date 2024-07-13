# FortiGate API Script

This script automates the process of creating objects and groups on FortiGate firewalls using the REST API. It reads configurations from a CSV file and supports adding objects to multiple groups. The script also provides detailed logging and can send email reports.

## Features

- Create objects (subnets and FQDNs) on FortiGate firewalls.
- Create groups and add objects to groups.
- Support for multiple firewalls and VDOMs.
- Detailed logging with configurable log file names.
- API throttling to avoid rate limits.
- Email reports with configurable success/error settings.
- Command-line arguments for flexibility.

## Requirements

- Python 3.6+
- `requests` library: Install using `pip install requests`

## Configuration

### `config.json`

The `config.json` file contains the configuration for the script, including firewall details, logging settings, API throttling, and email settings.

Example:

```json
{
    "firewalls": [
        {
            "name": "firewall1",
            "ip": "192.168.1.1",
            "api_token": "your_api_token_here",
            "vdoms": ["vdom1", "vdom2"]
        },
        {
            "name": "firewall2",
            "ip": "192.168.1.2",
            "api_token": "your_api_token_here",
            "vdoms": ["vdom1", "vdom2"]
        }
    ],
    "logging": {
        "enabled": true,
        "level": "INFO",
        "log_file": "script_%Y%m%d_%H%M%S.log"
    },
    "api_throttle": {
        "enabled": true,
        "interval": 1.0
    },
    "email_settings": {
        "smtp_server": "smtp.yourmailserver.com",
        "smtp_port": 25,
        "sender_email": "sender@yourdomain.com",
        "receiver_email": "receiver@yourdomain.com",
        "subject": "FortiGate API Script Report",
        "send_on_success": true,
        "send_on_error": true
    }
}
