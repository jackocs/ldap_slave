#!/bin/bash

date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

conn=$(docker exec -it ldap ldapsearch -LLL -H ldapi:// -Y EXTERNAL -b 'cn=Current,cn=Connections,cn=Monitor' -s base '(objectClass=*)' '*' '+'  2>/dev/null | grep monitorCounter: |awk '{print $2}' | sed -e 's/\r//g')

echo "(\"$date\":$conn}" > /tmp/monitorCounter.txt
