#!/bin/bash

service httpd stop
service edgy_critsd stop
# flush edge mongodb
EDGE_COLLECTIONS='stix uploads adapters.crits stats_indicators cache indicators_by_date peer_log peer_sessions'
for EDGE_COLLECTION in ${EDGE_COLLECTIONS}; do
    mongo inbox --eval "db.${EDGE_COLLECTION}.remove({})"
done
# flush crits mongodb
CRITS_COLLECTIONS='ips domains sample email indicators events'
for CRITS_COLLECTION in ${CRITS_COLLECTIONS}; do
    mongo crits --eval "db.${CRITS_COLLECTION}.remove({})"
done
# delete old logs
rm -f /opt/soltra/edge/repository/adapters/crits/edgy_crits*.log*

service httpd start
service edgy_critsd start
