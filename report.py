# -*- coding: utf-8 -*-
import csv
import os
import requests
from dotenv import load_dotenv
load_dotenv()
from datetime import datetime
from colorama import init, Fore, Back, Style
from tabulate import tabulate
init(autoreset=True)
SEVERITY_COLORS = {
    'CRITICAL': Fore.RED + Style.BRIGHT,
    'HIGH':     Fore.YELLOW + Style.BRIGHT,
    'MEDIUM':   Fore.CYAN,
    'LOW':      Fore.GREEN,
}
SEVERITY_ICON = {
    'CRITICAL': '[!!!]',
    'HIGH':     '[ !! ]',
    'MEDIUM':   '[  ! ]',
    'LOW':      '[  i ]',
}
def print_banner():
    banner = r"""
  _                 ____
 | |   ___  __ _  |  _ \  __ _ _ __ ___  ___ _ __
 | |  / _ \/ _` | | |_) |/ _` | '__/ __|/ _ \ '__|
 | |_| (_) | (_| | |  __/ (_| | |  \__ \  __/ |
 |____\___/ \__, | |_|   \__,_|_|  |___/\___|_|
            |___/  by Yesha
"""
    print(Fore.GREEN + Style.BRIGHT + banner)
def print_summary(findings, total_events, filepath):
    print(Fore.CYAN + '\n' + '='*60)
    print(Fore.CYAN + f'  SCAN RESULTS - {os.path.basename(filepath)}')
    print(Fore.CYAN + '='*60)
    print(f'  Total log events parsed : {Fore.WHITE}{total_events}')
    print(f'  Threats detected        : {Fore.RED}{len(findings)}')
    print(f'  Scan time               : {Fore.WHITE}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print(Fore.CYAN + '='*60 + '\n')
def print_findings(findings):
    if not findings:
        print(Fore.GREEN + Style.BRIGHT + '  [+] No threats detected. Log appears clean.')
        return
    table_data = []
    for f in findings:
        sev = f['severity']
        color = SEVERITY_COLORS.get(sev, '')
        icon = SEVERITY_ICON.get(sev, '[?]')
        table_data.append([
            color + icon + Style.RESET_ALL,
            color + sev + Style.RESET_ALL,
            Fore.WHITE + f['rule'],
            Fore.YELLOW + f['ip'],
            Fore.WHITE + f['detail']
        ])
    headers = ['', 'Severity', 'Rule', 'IP', 'Detail']
    print(tabulate(table_data, headers=headers, tablefmt='simple'))
    print()
def export_csv(findings, output_path='findings.csv'):
    if not findings:
        return
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f,
            fieldnames=['rule', 'severity', 'ip', 'detail', 'count'])
        writer.writeheader()
        writer.writerows(findings)
    print(Fore.GREEN + f'  [+] Findings exported to {output_path}')
def ai_threat_summary(findings):
    if not findings:
        return
    findings_text = '\n'.join([
        f"{f['severity']}: {f['rule']} - {f['detail']} (IP: {f['ip']})"
        for f in findings
    ])
    prompt = f"""You are a SOC analyst. Summarize these security findings
in plain English for a non-technical manager. Explain what happened,
what the attacker was likely trying to do, and recommended actions.
Findings:
{findings_text}
Keep it under 150 words. Use clear, direct language."""
    response = requests.post(
        'https://api.groq.com/openai/v1/chat/completions',
        headers={
            'Authorization': f'Bearer {os.environ.get("GROQ_API_KEY")}',
            'Content-Type': 'application/json'
        },
        json={
            'model': 'llama-3.3-70b-versatile',
            'max_tokens': 300,
            'messages': [{'role': 'user', 'content': prompt}]
        }
    )
    data = response.json()
    summary = data['choices'][0]['message']['content']
    print(Fore.MAGENTA + Style.BRIGHT + '\n  [AI] THREAT SUMMARY')
    print(Fore.MAGENTA + '  ' + '='*56)
    for line in summary.split('\n'):
        print(Fore.WHITE + '  ' + line)
    print()