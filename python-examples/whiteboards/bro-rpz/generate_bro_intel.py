#!/usr/bin/env python

import sys
import csv
import argparse

from RFAPI import RFAPI

intel_summ_link = lambda id_: 'https://www.recordedfuture.com/live/sc/entity/' + id_ 

meta_source = 'recordedfuture'

parser = argparse.ArgumentParser(description='Generate Bro Intel file.')
parser.add_argument('--ip_risk_file', type=argparse.FileType('rb'), help='Downloaded IP risk scores.')
parser.add_argument('--ip_risk_floor', type=int, default=90, help='Only include IPs with risk scores in [risk_floor, 100]')
parser.add_argument('--hash_risk_floor', type=int, default=90, help='Only include hashes with risk scores in [risk_floor, 100]')
parser.add_argument('--token', type=str, help='Recorded Future API token')
parser.add_argument('--do_notice', type=bool, default=True, help="meta.do.notice")
args = parser.parse_args()

do_notice = 'T' if args.do_notice else 'F'

# Header time.
print("#fields\tindicator\tindicator_type\tmeta.source\tmeta.url\tmeta.do_notice\tmeta.if_in")

# IP Addresses.
c = 0
with args.ip_risk_file:
    csv_fd = csv.DictReader(args.ip_risk_file)
    for row in csv_fd:
        risk = int(row['Risk'])
        if risk >= args.ip_risk_floor:
            ip_form = row['Name']
            if '/' in ip_form:
                # We don't want to include CIDR ranges.
                continue

            print('\t'.join([
                ip_form, 'Intel::ADDR',
                meta_source, intel_summ_link('ip:'+ip_form),
                do_notice, '-'
                ]))
            c += 1

# Hashes.
api = RFAPI(args.token)
hash_query = {
  "cluster": {
    "data_group": "Hash",
    "limit": 10000,
    "attributes": [
      {
        "name": "stats.metrics.riskScore",
        "range": {
          "gte": args.hash_risk_floor
        }
      }
    ]
  },
  "output": {
    "exclude": [
      "stats.entity_lists"
    ],
    "inline_entities": True
  },
  "search_type": "scan"
}
for page in api.paged_query(hash_query):
    for ev in page['events']:
        ent = ev['attributes']['entities'][0]
        print('\t'.join([
            ent['name'], 'Intel::FILE_HASH',
            meta_source, intel_summ_link(ent['id']),
            do_notice, 'Files::IN_HASH'
            ]))
        c += 1

sys.stderr.write('Generated intel for {0} indicators.\n'.format(c))
