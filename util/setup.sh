#!/bin/bash

#
# install soltra edge crits adapter
#

yum install -y soltra-edge-python-pyyaml \
    soltra-edge-python-requests \
    soltra-edge-python-docopt \
    soltra-edge-python-logbook
chown -R repo.repo /opt/soltra/edge/repository/adapters/crits/
chmod -R ug+rw,o-rwx /opt/soltra/edge/repository/adapters/crits/
find /opt/soltra/edge/repository/adapters/crits/ -type d -exec chmod ug+x {} \;
chmod a+x /opt/soltra/edge/repository/adapters/crits/*.py
chmod a+x /opt/soltra/edge/repository/adapters/crits/util/*
ln -s /opt/soltra/edge/repository/adapters/crits/init.d-edgy_critsd /etc/init.d/edgy_critsd
chkconfig --level 345 edgy_critsd on
echo '/opt/soltra/edge/repository/lib' >> /opt/soltra/edge/lib/python2.7/site-packages/repository.pth
echo 'edgy_critsd successfully installed. Edit config.yaml and then start the service (`service edgy_critsd start`).'

# Copy over existing .config.yaml
yes n | cp -i /opt/soltra/edge/repository/adapters/crits/.config.yaml /opt/soltra/edge/repository/adapters/crits/config.yaml
