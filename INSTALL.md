How to install the Soltra Edge CRITs adapter
============================================

0. `scp crits.tgz root@<address of your edge instance>:.`
1. `ssh root@<address of your edge instance>`
2. `cd /opt/soltra/edge/repository/adapters/`
3. `tar xzf /root/crits.tgz`
4. `cd crits/`
5. `./util/setup.sh`
6. Edit config.yaml and put in the appropriate parameters. (It's
   straightforward and well-commented.) The main thing to focus on is
   the address/port of your Edge and CRITs instances and
   username/password (or in the case of CRITs, username and api key.)
7. `service edgy_critsd start`
8. `tail -f edgy_crits.log` (Optionally, just to make sure that the
   initial synchronization process is going smoothly.)
