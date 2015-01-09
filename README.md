Installing the Soltra Edge CRITs adapter
========================================
1) scp crits.tgz to your edge instance
2) cd /opt/soltra/edge/repository/adapters/
3) tar xzf /path/to/crits.tgz
4) edit /opt/soltra/edge/repository/adapters/crits/config.yaml
5) run /opt/soltra/edge/repository/adapters/crits/util/setup.sh
6) service edgy_critsd start
