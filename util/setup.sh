#!/bin/bash

yum install -y libyaml-devel
/opt/soltra/edge/bin/pip2.7 install Logbook==0.8.1
/opt/soltra/edge/bin/pip2.7 install PyYAML==3.11
/opt/soltra/edge/bin/pip2.7 install docopt==0.6.2
/opt/soltra/edge/bin/pip2.7 install ipaddr==2.1.11
/opt/soltra/edge/bin/pip2.7 install requests==2.5.1
chown -R repo.repo /opt/soltra/edge/repository/adapters/crits/
chmod -R ug+rw,o-rwx /opt/soltra/edge/repository/adapters/crits/
find /opt/soltra/edge/repository/adapters/crits/ -type d -exec chmod ug+x {} \;
chmod a+x /opt/soltra/edge/repository/adapters/crits/*.py
chmod a+x /opt/soltra/edge/repository/adapters/crits/util/*.{py,sh}
ln -s /opt/soltra/edge/repository/adapters/crits/init.d-edgy_critsd /etc/init.d/edgy_critsd
chkconfig --level 345 edgy_critsd on
echo '/opt/soltra/edge/repository/lib' >> /opt/soltra/edge/lib/python2.7/site-packages/repository.pth
