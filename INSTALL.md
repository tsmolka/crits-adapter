How to install the Soltra Edge CRITs adapter
============================================

1. Login via ssh as the root user on Edge
2. Enter the Edge adapters directory: `cd
   /opt/soltra/edge/repository/adapters/`
3. Download the adapter: `wget
   https://github.com/security-automation/crits-adapter/archive/master.zip`
4. Extract the adapter: `unzip master.zip`
5. Rename the adapter to 'crits' (Important!): `mv
   crits-adapter-master crits`
6. Enter the adapter directory: `cd crits/`
7. Run the setup bash script: `./util/setup.sh`
8. Edit config.yaml and put in the appropriate parameters. It's
   straightforward and well-commented. The main thing to focus on is
   the address/port of your Edge and CRITs instances and
   username/password (or in the case of CRITs, username and api key.)
9. Start the adapter daemon: `service edgy_critsd start`
10. Optionally, just to make sure that the initial synchronization
    process is going smoothly: `tail -f edgy_crits.log`
