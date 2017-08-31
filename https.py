#!/bin/python3

import sys
import http.client

conn = http.client.HTTPSConnection(sys.argv[1], 443)
conn.request("GET", "/")
print(conn.getresponse().read())
conn.close()
