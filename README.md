About the Soltra Edge CRITs adapter
===================================

Intent
------
* Enable the use of Soltra Edge as a transport mechanism for threat
  intelligence data between distributed CRITs instances via
  bidirectional translation between CRITs JSON and STIX/CybOX and
  bidirectional synchronization between CRITs (via API) and Soltra
  Edge (via TAXII).


Capabilities
------------
* CRITs to Soltra Edge: translation of emails, IP addresses, samples,
  domains, and indicators.
* Soltra Edge to CRITs: translation of selected CybOX Observable
  objects (Domain Name, File, Address, Email Message) and STIX
  Indicator objects.


Constraints
-----------
* CRITs samples: while the CRITs API (get) allows the retrieval of all
  available sample metadata, for inserting (post) samples currently
  the CRITs API is limited to file name and MD5 hash. There is an [open
  GitHub issue][0] for this.

* CRITs releasability flag: while the CRITs API (get) allows filtering
  data retrieval based on a releasability flag, for inserting (post)
  data the CRITs API currently does not support setting a
  releasability flag.There is an [open GitHub issue][1] for this.

* STIX indicator objects: by last count there are at least
  [12 different ways][2] to express context between 2 IP addresses.
  This adapter currently only supports STIX indicators containing one
  inline CybOX Observable Composition externally referencing (idref)
  the related CybOX Observable objects (#2 in [the IP address example][2].)


Commands
--------
* **Note**: all commands provide detailed usage info when passed the
  `--help` flag
* datagen.py
    * Description: Inject randomly generated observable / indicator
      data into CRITs or Soltra Edge (useful for development and
      testing)
    * Example usage: `./datagen.py --inject --type=edge
      --target=localhost --datatype=indicator --count=1000` (as repo user)
* edgy_critsd.py
    * Description: Daemon that continually syncs data between
      configured CRITs and Soltra Edge instances.
    * Example usage: `service edgy_critsd start` (as root)
* edgy_crits.py
    * Description: Performs a one-off, unidirectional sync between a
      configured CRITs and Soltra Edge instance
    * Example usage: `./edgy_crits.py --sync-crits-to-edge
      --source=localhost --destination=localhost` (as repo user)
* util/flush.sh
    * Description: Flush all indicator and observable data from
      (localhost) CRITs and Edge MongoDB collections, edgy_crits
      logfiles, adapter-specific MongoDB collections (useful for
      development and testing)
    * Example usage: `./util/flush.sh` (as root)
* util/setup.sh
    * Description: Install adapter dependencies, fix permissions, and
      configure edgy_critsd as a service set to start on boot.
    * Example usage: `./util/setup.sh` (as root)


12 ways to express context between 2 IP addresses
-------------------------------------------------
1. Indicator, with two inline IPv4 AddressObjects
2. Indicator, with two referenced IPv4 AddressObjects
3. Indicator, with one inline IPv4 AddressObject using comma notation (127.0.0.1##comma##127.0.0.2)
4. Indicator, with one referenced IPv4 AddressObject using comma notation (127.0.0.1##comma##127.0.0.2)
5. A composite indicator including a single indicator, with two inline IPv4 AddressObjects
6. A composite indicator including a single indicator, with two referenced IPv4 AddressObjects
7. A composite indicator including a single indicator, with one referenced IPv4 AddressObject using comma notation (127.0.0.1##comma##127.0.0.2)
8. A composite indicator including a single indicator, with one inline IPv4 AddressObject using comma notation (127.0.0.1##comma##127.0.0.2)
9. A composite indicator with two indicators. Each indicator has a single inline IPv4 AddressObjects
10. A composite indicator with two indicators. Each indicator has a single referenced IPv4 AddressObjects
11. Two AddressObjects, no indicators, and "These IP addresses are malicious" placed in the Title field of the STIX_Header
12. One AddressObject using comma notation (127.0.0.1##comma##127.0.0.2), no indicators, and "These IP addresses are malicious" placed in the Title field of the STIX_Header


[0]: https://github.com/crits/crits/issues/362
[1]: https://github.com/crits/crits/issues/361
[2]: #12-ways-to-express-context-between-2-ip-addresses
