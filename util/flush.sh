#!/bin/bash

service httpd stop
service edgy_critsd stop
# flush edge mongodb
mongo inbox --eval "db.stix.remove({})"
mongo inbox --eval "db.uploads.remove({})"
mongo inbox --eval "db.adapters.crits.remove({})"
mongo inbox --eval "db.stats_indicators.remove({})"
mongo inbox --eval "db.cache.remove({})"
mongo inbox --eval "db.indicators_by_date.remove({})"
mongo inbox --eval "db.uploads.remove({})"
mongo inbox --eval "db.peer_log.remove({})"
mongo inbox --eval "db.peer_sessions.remove({})"
# flush crits mongodb
mongo crits --eval "db.ips.remove({})"
mongo crits --eval "db.domains.remove({})"
mongo crits --eval "db.sample.remove({})"
mongo crits --eval "db.email.remove({})"
mongo crits --eval "db.indicators.remove({})"
# delete old logs
rm -f /opt/soltra/edge/repository/adapters/crits/edgy_crits*.log*

service httpd start
service edgy_critsd start
