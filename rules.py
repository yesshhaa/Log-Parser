# -*- coding: utf-8 -*-
from collections import defaultdict
from datetime import datetime

BRUTE_FORCE_THRESHOLD = 5
CRED_STUFF_THRESHOLD = 3
ADMIN_BRUTE_THRESHOLD = 3
AFTER_HOURS_START = 0
AFTER_HOURS_END = 6

def check_brute_force(events):
    findings = []
    ip_fails = defaultdict(int)
    for e in events:
        if e['type'] == 'failed':
            ip_fails[e['ip']] += 1
    for ip, count in ip_fails.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            findings.append({
                'rule': 'Brute Force',
                'severity': 'CRITICAL',
                'ip': ip,
                'detail': f'{count} failed login attempts',
                'count': count
            })
    return findings

def check_credential_stuffing(events):
    findings = []
    ip_users = defaultdict(set)
    for e in events:
        if e['type'] == 'failed':
            ip_users[e['ip']].add(e['user'])
    for ip, users in ip_users.items():
        if len(users) >= CRED_STUFF_THRESHOLD:
            findings.append({
                'rule': 'Credential Stuffing',
                'severity': 'CRITICAL',
                'ip': ip,
                'detail': f'Tried {len(users)} usernames: {", ".join(users)}',
                'count': len(users)
            })
    return findings

def check_success_after_failure(events):
    findings = []
    failed_ips = {e['ip'] for e in events if e['type'] == 'failed'}
    success_ips = [e for e in events if e['type'] == 'accepted']
    for e in success_ips:
        if e['ip'] in failed_ips:
            findings.append({
                'rule': 'Success After Failures',
                'severity': 'HIGH',
                'ip': e['ip'],
                'detail': f'Successful login for {e["user"]} after prior failures',
                'count': 1
            })
    return findings

def check_after_hours(events):
    findings = []
    for e in events:
        if e['type'] != 'accepted':
            continue
        try:
            ts = datetime.strptime(e['timestamp'], '%b %d %H:%M:%S')
            if AFTER_HOURS_START <= ts.hour < AFTER_HOURS_END:
                findings.append({
                    'rule': 'After-Hours Login',
                    'severity': 'MEDIUM',
                    'ip': e['ip'],
                    'detail': f'Login for {e["user"]} at {e["timestamp"]}',
                    'count': 1
                })
        except ValueError:
            pass
    return findings

def check_root_attempts(events):
    findings = []
    root_events = [e for e in events if e.get('user') == 'root']
    if root_events:
        ips = {e['ip'] for e in root_events}
        findings.append({
            'rule': 'Root Login Attempt',
            'severity': 'HIGH',
            'ip': ', '.join(ips),
            'detail': f'{len(root_events)} root login attempt(s)',
            'count': len(root_events)
        })
    return findings

def check_path_traversal(events):
    findings = []
    for e in events:
        if e.get('type') == 'http_request' and '../' in e.get('path', ''):
            findings.append({
                'rule': 'Path Traversal',
                'severity': 'CRITICAL',
                'ip': e['ip'],
                'detail': f'Traversal attempt: {e["path"]}',
                'count': 1
            })
    return findings

def check_admin_brute(events):
    findings = []
    ip_401 = defaultdict(int)
    for e in events:
        if e.get('type') == 'http_request' and e.get('status') == 401:
            ip_401[e['ip']] += 1
    for ip, count in ip_401.items():
        if count >= ADMIN_BRUTE_THRESHOLD:
            findings.append({
                'rule': 'Admin Brute Force',
                'severity': 'HIGH',
                'ip': ip,
                'detail': f'{count} unauthorized admin access attempts',
                'count': count
            })
    return findings

def run_all_rules(events, log_type):
    findings = []
    if log_type == 'auth':
        findings += check_brute_force(events)
        findings += check_credential_stuffing(events)
        findings += check_success_after_failure(events)
        findings += check_after_hours(events)
        findings += check_root_attempts(events)
    elif log_type == 'apache':
        findings += check_path_traversal(events)
        findings += check_admin_brute(events)
    return findings