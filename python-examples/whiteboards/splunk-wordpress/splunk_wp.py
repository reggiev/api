#!/usr/bin/env python
'''Query the Splunk server for suspicious activity by unknown clients towards
our external web.'''

import splunklib.client as client
import splunklib.results as results
import datetime

HOST = "localhost"
PORT = 8089
USERNAME = "username"
PASSWORD = "password"
SPLUNK_TIMEFMT = '%Y-%m-%dT%H:%M:%S.000%z'

def _service(host, port, username, password):
    'Create a Service instance and log in.'

    return client.connect(host=host, port=port,
                          username=username,
                          password=password)

def _query(service):
    'Run the query and return the result.'

    end = datetime.datetime.now()
    start = end - datetime.timedelta(days=7)
    searchquery_oneshot = ''.join([
        'search index=* ',
        '[search index=* sourcetype=haproxy wordpress-external ',
        '((wp-admin NOT admin-ajax.php) OR xmlrpc.php) ',
        '| localop ',
        '| lookup rf_threatfeed Name as ext_client_ip OUTPUT ',
        '  Risk, RiskString, EvidenceDetails ',
        '| fields http_request, Risk, RiskString, EvidenceDetails, ',
        '  http_result, ext_client_ip ',
        '| where Risk>0 | stats values(http_request) AS http_request] ',
        '| localop ',
        '| lookup rf_threatfeed Name as ext_client_ip OUTPUT ',
        '  Risk, RiskString, EvidenceDetails ',
        '| fillnull value=0 Risk | where Risk=0',
        '| stats dc(http_request) AS url_count by ext_client_ip ',
        '| where url_count < 2',
        '| fields ext_client_ip'
    ])
    
    oneshotsearch_results = service.jobs.oneshot(
        searchquery_oneshot,
        earliest_time=start.strftime(SPLUNK_TIMEFMT),
        latest_time=end.strftime(SPLUNK_TIMEFMT))

    reader = results.ResultsReader(oneshotsearch_results)
    return [row['ext_client_ip'] for row in reader]

if __name__ == '__main__':
    'Main starting point.'

    service = _service(HOST, PORT, USERNAME, PASSWORD)
    ips = _query(service)
    print '\n'.join(ips)
