# -*- coding: utf-8 -*-
import argparse
import sys
from parser import auto_parse
from rules import run_all_rules
from report import print_banner, print_summary, print_findings, export_csv, ai_threat_summary
def main():
    print_banner()
    arg = argparse.ArgumentParser(
        description='Log Parser - SOC threat detection tool'
    )
    arg.add_argument('--file', required=True, help='Path to log file')
    arg.add_argument('--export', action='store_true', help='Export findings to CSV')
    arg.add_argument('--output', default='findings.csv', help='CSV output path')
    arg.add_argument('--ai', action='store_true', help='Generate AI-powered plain-English threat summary')
    args = arg.parse_args()
    print(f' [*] Parsing: {args.file}')
    events, log_type = auto_parse(args.file)
    if not events:
        print(' [!] No events parsed. Check the file path and format.')
        sys.exit(1)
    print(f' [*] Detected format : {log_type}')
    print(f' [*] Events loaded   : {len(events)}')
    findings = run_all_rules(events, log_type)
    print_summary(findings, len(events), args.file)
    print_findings(findings)
    if args.export:
        export_csv(findings, args.output)
    if args.ai:
        ai_threat_summary(findings)
if __name__ == '__main__':
    main()