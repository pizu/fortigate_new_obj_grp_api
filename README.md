# FortiGate API Script To Create Objects & Groups

This script automates the process of creating objects and groups on FortiGate firewalls using the REST API. It reads configurations from a CSV file and supports adding objects to multiple groups. The script also provides detailed logging and can send email reports.

## Features

- Create objects (subnets and FQDNs) on FortiGate firewalls.
- Create groups and add objects to groups.
- Support for multiple firewalls and VDOMs.
- Detailed logging with configurable log file names.
- API throttling to avoid rate limits.
- Email reports with configurable both(Success & Error)/error settings.
- Command-line arguments for flexibility.

## Requirements

- Python 3.6+
- `requests` library: Install using `pip install requests`

## Setup and Configuration

1. **Prepare `configs/config.json`**: Define general settings including logging preferences, API throttling settings, and email settings.
2. **Prepare `configs/firewalls.json`**: Define the configuration for all firewalls.
3. **Clone the repository**:
    ```sh
    git clone https://github.com/pizu/fortigate_new_obj_grp_api.git
    ```
4. **Navigate to the repository**:
    ```sh
    cd fortigate_new_obj_grp_api
    ```

## Running the Script

### Command-Line Arguments
- Firewall name (e.g., `firewall1`)
- VDOM name (e.g., `vdom1`)
- Path to the CSV file (e.g., `objects.csv`)
- Optional: Email address to send the report to (e.g., `email@example.com`)
- Optional: Report type (`both` or `error`)
- Flags: `--config configs/config.json`, `--firewall-config configs/firewalls.json`, `--debug`, `--no-throttle`, `--no-email`, `--no-print`


### Example Script Usage
Once the repository is set up, here’s an example of how to run your script.

Ensure your configs/config.json and configs/firewalls.json are properly configured.
Prepare your CSV file (objects.csv) with the necessary object details.
Run the script with the appropriate arguments:
```sh
python fortigate_script.py firewall1 vdom1 objects.csv email@example.com both --config configs/config.json --firewall-config configs/firewalls.json --debug
```

## Requirements
```sh
pip install -r requirements.txt
```


### Full Configuration Files

Here are the full configurations for `configs/config.json` and `configs/firewalls.json`.

#### `configs/config.json`

```json
{
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
        "smtp_port": 587,
        "sender_email": "sender@yourdomain.com",
        "subject": "FortiGate API Script Report",
        "send_on_success": true,
        "send_on_error": true
    },
    "last_script_run": "2024-07-13 12:00:00"
}

```
#### `configs/firewalls.json`
```json
{
    "firewalls": [
        {
            "name": "Test_FW_1",
            "ip": "192.168.1.1",
            "api_token": "your_api_firewall_token_here",
            "vdoms": [
                "VDOM1",
                "VDOM2",
                "VDOM3"
            ]
        },
        {
            "name": "firewall2",
            "ip": "192.168.1.2",
            "api_token": "your_api_firewall_token_here",
            "vdoms": [
                "ABC",
                "CDEF"
            ]
        }
    ]
}
```

## CSV File
The CSV file should contain the objects and groups to be created. The file should have the following columns: **name**, **type**, **value**, and **groups**. The groups column can contain multiple groups separated by commas.

## Example:
```
name,type,value,groups
webserver1,subnet,192.168.1.0/24,group1
webserver2,fqdn,www.example.com,group1,group2
database1,subnet,192.168.2.0/24,group2
singlehost,subnet,192.168.3.1,group1,group3
```

In the above example, note that singlehost is specified **without** a subnet mask. The script will automatically append **/32** to this entry, treating it as a single IP address.

# Usage
### Command-Line Arguments
- **firewall**: Name of the firewall to use (from config file)
- **vdom**: Name of the VDOM to use
- **csv_file**: Path to the CSV file
- **--config**: Path to the configuration file (default: config.json)
- **--debug**: Enable debug logging
- **--no-throttle**: Disable API throttling
- **--no-email**: Disable email report
- **--no-print**: Disable printing report to console
```


## Sending Reports via Email
The script can send the report to a specified email address. The email settings are defined in configs/config.json under the email_settings section. To specify the email address and report type (both or error), use the following arguments:

```
python fortigate_script.py firewall1 vdom1 objects.csv email@example.com both
```
