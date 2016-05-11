#!/usr/bin/env python

import sys
import csv
import json
import argparse

parser = argparse.ArgumentParser(description='Generate DNS RPZ rules.')
parser.add_argument('--ip_risk_file', type=argparse.FileType('rb'), help='Downloaded risk scores.')
parser.add_argument('--ip_risk_floor', type=int, default=90, help='Only include risk scores in [risk_floor, 100]')
args = parser.parse_args()

c = 0
with args.ip_risk_file:
    csv_fd = csv.DictReader(args.ip_risk_file)
    for row in csv_fd:
        risk = int(row['Risk'])
        if risk >= args.ip_risk_floor:
            # Prefix check
            prefix = "32"
            ip_form = row['Name']
            if '/' in ip_form:
                # Skip CIDR ranges.
                continue

            # Reverse.
            ip_form = '.'.join(ip_form.split('.')[::-1])

            # Finalize rule.
            ip_form = prefix + "." + ip_form + '.rpz-ip'

            evidence = json.loads(row['EvidenceDetails'])
            print "; Risk: {0} Triggered Rules: {1}".format(row['Risk'], row['RiskString'])
            for ev_dets in evidence['EvidenceDetails']:
                es = ev_dets['EvidenceString']
                es = es.replace('\n', ' ')
                print ";; {0} : {1}".format(ev_dets['Rule'].encode('utf-8'), es.encode('utf-8'))
            print "{0} CNAME .\n".format(ip_form)
            c += 1

sys.stderr.write('Generated {0} rules.\n'.format(c))
