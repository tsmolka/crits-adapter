How to install the Soltra Edge CRITs adapter
============================================

Upload the crits adapter

0. Upload the adapter to your instance of Soltra Edge

   `scp crits.tgz root@<address of your edge instance>:.`
1. Login to Edge

   `ssh root@<address of your edge instance>`
2. Enter the Edge adapters directory

   `cd /opt/soltra/edge/repository/adapters/`
3. Extract the adapter into the adapters directory

   `tar xzf /root/crits.tgz`
4. Enter the adapter's directory

   `cd crits/`
5. Run the setup bash script

   `./util/setup.sh`
6. Edit config.yaml and put in the appropriate parameters. (It's
   straightforward and well-commented.) The main thing to focus on is
   the address/port of your Edge and CRITs instances and
   username/password (or in the case of CRITs, username and api key.)
7. Start the adapter daemon

   `service edgy_critsd start`
8. Optionally, just to make sure that the initial synchronization process is going smoothly.

   `tail -f edgy_crits.log`
