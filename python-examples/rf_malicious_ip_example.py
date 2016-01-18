# Example API code for use with RFAPI.py module

import sys

from optparse import OptionParser
from StringIO import StringIO
from RFAPI import RFAPI

features = ["Name", "RFURL"]

#Command line options 
parser = OptionParser()
                     
parser.add_option("-t", dest="token", 
                        action="store", 
                        default=False, 
                        help="Recorded Future TOKEN - Required.")
                
(options, args) = parser.parse_args()
   
# Set token     
if options.token:
    token = options.token
else:
    parser.print_help()
    sys.exit()


# The RF query 
#
# Notice that we're looking for IPs with maliciousHits 
# OR infoSecHits, relatedHashCount OR relatedMalwareCount > 0
#
# We are excluding certin IP addresses - loopback, etc.
#
# Try the RF API Explorer for assistance in query syntax, 
# fields and testing: https://api.recordedfuture.com/explore.html
# Log in using your RF API token. If you do not have one, 
# please reach out to support@recordedfuture.com
q = {
  "cluster": {
    "data_group": "IpAddress",
    "attributes": [
      [
        {
          "range": {
            "gt": 0
          },
          "name": "stats.metrics.maliciousHits"
        },
        {
          "range": {
            "gt": 0
          },
          "name": "stats.metrics.infoSecHits"
        },
        {
          "range": {
            "gt": 0
          },
          "name": "stats.metrics.relatedHashCount"
        },
        {
          "range": {
            "gt": 0
          },
          "name": "stats.metrics.relatedMalwareCount"
        }
      ],
      {
        "not": {
          "ip": "10.0.0.0/8"
        }
      },
      {
        "not": {
          "ip": "172.16.0.0/12"
        }
      },
      {
        "not": {
          "ip": "192.168.0.0/16"
        }
      },
      {
        "not": {
          "ip": "127.0.0.1"
        }
      },
      {
        "not": {
          "ip": "0.0.0.0"
        }
      }
    ],
    "limit": 10
  },
  "output": {
    "exclude": [
      "stats"
    ],
    "inline_entities": True
  }
}

# Using RFAPI module, run query
# Note: To pull back all results, use rfqapi.paged_query(q)
# and a higher limit. 
rfqapi = RFAPI(token)
result = rfqapi.query(q)
 
# Display the results (in this case, limit is 1)    
for res in result['events']:
    print "Event: \n"
    print str(res) + '\n'