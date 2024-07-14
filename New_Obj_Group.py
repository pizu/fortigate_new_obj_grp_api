#!/usr/bin/env python
import csv
import json
import sys
import requests
import time
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import argparse
from datetime import datetime

# Set up logging
def setup_logging(logging_config):
    if logging_config['enabled']:
        log_level = getattr(logging, logging_config['level'].upper(), logging.INFO)
        log_file = datetime.now().strftime(logging_config['log_file'])
        logging.basicConfig(level=log_level,
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                            filename=log_file)

# Load configuration file
def load_config(file_path):
    with open(file_path) as config_file:
        return json.load(config_file)

# Save configuration file
def save_config(file_path, config):
    with open(file_path, 'w') as config_file:
        json.dump(config, config_file, indent=4)
    logging.info(f"Configuration file {file_path} updated with the last run time.")

# Load and validate CSV file
def load_and_validate_csv(file_path, report):
    objects = []
    groups = {}
    with open(file_path, mode='r') as file:
        csv_reader = csv.DictReader(file)
        line_number = 1
        for row in csv_reader:
            line_number += 1
            # Validate required fields
            if not row['name'] or not row['type'] or not row['value']:
                report["errors"].append(f"Missing required field at line {line_number}")
                logging.error(f"Missing required field at line {line_number}")
                continue
            if row['type'] not in ['subnet', 'fqdn']:
                report["errors"].append(f"Invalid type '{row['type']}' at line {line_number}")
                logging.error(f"Invalid type '{row['type']}' at line {line_number}")
                continue
            # Add object
            objects.append({
                "name": row['name'],
                "type": row['type'],
                "value": row['value']
            })
            # Process groups
            if row['groups']:
                group_list = row['groups'].split(',')
                for group in group_list:
                    group = group.strip()
                    if group:
                        if group not in groups:
                            groups[group] = []
                        groups[group].append(row['name'])
    return objects, groups

# Validate firewall
def validate_firewall(fw, token):
    url = f"https://{fw}/api/v2/cmdb/system/global"
    headers = {'Authorization': f"Bearer {token}"}
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        logging.info(f"Successfully validated firewall {fw}")
        return True
    else:
        logging.error(f"Failed to validate firewall {fw}: {response.text}")
        return False

# Validate VDOM
def validate_vdom(fw, vdom, token):
    url = f"https://{fw}/api/v2/cmdb/system/vdom/{vdom}"
    headers = {'Authorization': f"Bearer {token}"}
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        logging.info(f"Successfully validated VDOM {vdom} on firewall {fw}")
        return True
    else:
        logging.error(f"Failed to validate VDOM {vdom} on firewall {fw}: {response.text}")
        return False

# Create object
def create_object(fw, vdom, token, obj):
    url = f"https://{fw}/api/v2/cmdb/firewall/address?vdom={vdom}"
    headers = {'Authorization': f"Bearer {token}"}
    data = {
        "name": obj['name'],
        "type": obj['type']
    }
    if obj['type'] == 'subnet':
        data['subnet'] = obj['value']
    elif obj['type'] == 'fqdn':
        data['fqdn'] = obj['value']
    
    # Check if the object already exists
    existing_objects_response = requests.get(url, headers=headers, verify=False)
    if existing_objects_response.status_code == 200:
        existing_objects = existing_objects_response.json().get('results', [])
        if any(existing_obj['name'] == obj['name'] for existing_obj in existing_objects):
            report["skipped"].append(f"Object {obj['name']} already exists")
            logging.info(f"Skipped creating object {obj['name']} on {fw}: already exists")
            return

    response = requests.post(url, headers=headers, json=data, verify=False)
    if response.status_code == 200:
        report["created_objects"].append(obj['name'])
        logging.info(f"Successfully created object {obj['name']} on {fw}")
    else:
        report["errors"].append(f"Error creating object {obj['name']} on {fw}: {response.text}")
        logging.error(f"Error creating object {obj['name']} on {fw}: {response.text}")

# Create group
def create_group(fw, vdom, token, group):
    url = f"https://{fw}/api/v2/cmdb/firewall/addrgrp?vdom={vdom}"
    headers = {'Authorization': f"Bearer {token}"}
    data = {
        "name": group
    }

    # Check if the group already exists
    existing_groups_response = requests.get(url, headers=headers, verify=False)
    if existing_groups_response.status_code == 200:
        existing_groups = existing_groups_response.json().get('results', [])
        if any(existing_grp['name'] == group for existing_grp in existing_groups):
            report["skipped"].append(f"Group {group} already exists")
            logging.info(f"Skipped creating group {group} on {fw}: already exists")
            return

    response = requests.post(url, headers=headers, json=data, verify=False)
    if response.status_code == 200:
        report["created_groups"].append(group)
        logging.info(f"Successfully created group {group} on {fw}")
    else:
        report["errors"].append(f"Error creating group {group} on {fw}: {response.text}")
        logging.error(f"Error creating group {group} on {fw}: {response.text}")

# Add group memberships
def add_group_memberships(fw, vdom, token, group, members):
    url = f"https://{fw}/api/v2/cmdb/firewall/addrgrp/{group}?vdom={vdom}"
    headers = {'Authorization': f"Bearer {token}"}
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code != 200:
        report["errors"].append(f"Error fetching group {group} on {fw}: {response.text}")
        logging.error(f"Error fetching group {group} on {fw}: {response.text}")
        return

    existing_group = response.json().get('results', [{}])[0]
    current_members = {member['name'] for member in existing_group.get('member', [])}
    new_members = [{"name": member.strip()} for member in members if member.strip() not in current_members]

    if not new_members:
        report["skipped"].append(f"All members of group {group} already exist on {fw}")
        logging.info(f"Skipped adding members to group {group} on {fw}: all members already exist")
        return

    data = {"member": [{"name": member} for member in current_members.union(set(m['name'] for m in new_members))]}
    response = requests.put(url, headers=headers, json=data, verify=False)
    if response.status_code == 200:
        report["group_memberships"].append({
            "group": group,
            "members_added": [member['name'] for member in new_members]
        })
        logging.info(f"Successfully added members to group {group} on {fw}")
    else:
        report["errors"].append(f"Error adding members to group {group} on {fw}: {response.text}")
        logging.error(f"Error adding members to group {group} on {fw}: {response.text}")

# Send report
def send_report(email_settings, report, email, report_type):
    if report_type not in ['both', 'error']:
        logging.error(f"Invalid report type: {report_type}")
        return

    if report_type == 'error' and not report['errors']:
        return

    msg = MIMEMultipart()
    msg['From'] = email_settings['sender_email']
    msg['To'] = email
    msg['Subject'] = email_settings['subject']

    body = json.dumps(report, indent=4)
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(email_settings['smtp_server'], email_settings['smtp_port'])
        text = msg.as_string()
        server.sendmail(email_settings['sender_email'], email, text)
        server.quit()
        logging.info(f"Email report sent successfully to {email}")
    except Exception as e:
        logging.error(f"Failed to send email report to {email}: {e}")

# Save report to file
def save_report_to_file(report):
    filename = datetime.now().strftime("report_%Y%m%d_%H%M%S.json")
    with open(filename, 'w') as file:
        json.dump(report, file, indent=4)
    logging.info(f"Report saved to {filename}")

# Command-line arguments
parser = argparse.ArgumentParser(description="FortiGate API Script")
parser.add_argument('firewall', help="Name of the firewall to use (from config file)")
parser.add_argument('vdom', help="Name of the VDOM to use")
parser.add_argument('csv_file', help="Path to the CSV file")
parser.add_argument('--config', default='config.json', help="Path to the configuration file")
parser.add_argument('--debug', action='store_true', help="Enable debug logging")
parser.add_argument('--no-throttle', action='store_true', help="Disable API throttling")
parser.add_argument('--no-email', action='store_true', help="Disable email report")
parser.add_argument('--no-print', action='store_true', help="Disable printing report to console")
parser.add_argument('email', nargs='?', default=None, help="Email address to send the report to")
parser.add_argument('report_type', nargs='?', default=None, help="Report type: both or error")
args = parser.parse_args()

# Validate email and report_type arguments
if args.email and not args.report_type:
    parser.error("If --email is provided, --report_type must also be provided.")
if args.report_type and args.report_type not in ['both', 'error']:
    parser.error("--report_type must be 'both' or 'error'.")

# Load configuration
config = load_config(args.config)
firewalls = config['firewalls']
email_settings = config['email_settings']
api_throttle_config = config['api_throttle']

# Set up logging
if args.debug:
    config['logging']['level'] = 'DEBUG'
setup_logging(config['logging'])

# Initialize report
report = {
    "created_objects": [],
    "created_groups": [],
    "group_memberships": [],
    "skipped": [],
    "errors": []
}

# Load and validate CSV data
objects, groups = load_and_validate_csv(args.csv_file, report)

# Check if there were any errors during CSV validation
if report['errors']:
    # Print the report to console if enabled
    if not args.no_print:
        print(json.dumps(report, indent=4))
    # Save the report to a file
    save_report_to_file(report)
    # Send the report via email if configured
    if not args.no_email and args.email:
        send_report(email_settings, report, args.email, args.report_type)
    sys.exit(1)

# Update the last run time in the configuration file
config['last_update'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
save_config(args.config, config)

# Process each firewall
for fw_config in firewalls:
    if fw_config['name'] == args.firewall:
        fw_ip = fw_config['ip']
        api_token = fw_config['api_token']
        vdoms = fw_config['vdoms']

        if args.vdom not in vdoms:
            logging.error(f"VDOM {args.vdom} is not available on firewall {args.firewall}")
            report["errors"].append(f"VDOM {args.vdom} is not available on firewall {args.firewall}")
            sys.exit(1)

        if not validate_firewall(fw_ip, api_token) or not validate_vdom(fw_ip, args.vdom, api_token):
            sys.exit(1)

        # Create objects
        for obj in objects:
            create_object(fw_ip, args.vdom, api_token, obj)
            if not args.no_throttle and api_throttle_config['enabled']:
                time.sleep(api_throttle_config['interval'])

        # Create groups
        for group in groups.keys():
            create_group(fw_ip, args.vdom, api_token, group)
            if not args.no_throttle and api_throttle_config['enabled']:
                time.sleep(api_throttle_config['interval'])

        # Add group memberships
        for group, members in groups.items():
            add_group_memberships(fw_ip, args.vdom, api_token, group, members)
            if not args.no_throttle and api_throttle_config['enabled']:
                time.sleep(api_throttle_config['interval'])

# Print the report to console if enabled
if not args.no_print:
    print(json.dumps(report, indent=4))

# Save the report to a file
save_report_to_file(report)

# Send the report via email if configured
if not args.no_email and args.email:
    send_report(email_settings, report, args.email, args.report_type)

