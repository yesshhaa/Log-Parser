# -*- coding: utf-8 -*-
import re
from datetime import datetime

AUTH_PATTERNS = {
    'failed': re.compile(
        r'(\w+ \d+ \d+:\d+:\d+).*Failed password for (\S+) from (\S+)'
    ),
    'accepted': re.compile(
        r'(\w+ \d+ \d+:\d+:\d+).*Accepted password for (\S+) from (\S+)'
    ),
    'invalid': re.compile(
        r'(\w+ \d+ \d+:\d+:\d+).*Invalid user (\S+) from (\S+)'
    ),
}

APACHE_PATTERN = re.compile(
    r'(\S+) \S+ \S+ \[(.+?)\] "(\S+) (\S+) HTTP.*" (\d+) (\d+)'
)

def parse_auth_log(filepath):
    events = []
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            for event_type, pattern in AUTH_PATTERNS.items():
                match = pattern.search(line)
                if match:
                    timestamp_str, user, ip = match.groups()
                    events.append({
                        'timestamp': timestamp_str,
                        'type': event_type,
                        'user': user,
                        'ip': ip,
                        'raw': line.strip()
                    })
                    break
    return events

def parse_apache_log(filepath):
    events = []
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            match = APACHE_PATTERN.search(line)
            if match:
                ip, timestamp, method, path, status, size = match.groups()
                events.append({
                    'timestamp': timestamp,
                    'type': 'http_request',
                    'ip': ip,
                    'method': method,
                    'path': path,
                    'status': int(status),
                    'raw': line.strip()
                })
    return events

def auto_parse(filepath):
    with open(filepath, 'r', errors='ignore') as f:
        sample = f.read(500)
    if 'sshd' in sample or 'Failed password' in sample:
        return parse_auth_log(filepath), 'auth'
    elif 'HTTP' in sample:
        return parse_apache_log(filepath), 'apache'
    else:
        print('[!] Unknown log format')
        return [], 'unknown'