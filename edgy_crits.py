#!/usr/bin/env python2.7


from docopt import docopt
from sys import path as python_path
import os.path
python_path.append('./lib_')
from crits_ import crits2edge
from edge_ import edge2crits
import util_
import log_
import db_


__version__ = '0.2'
app_path = os.path.split(os.path.abspath(__file__))[0]
default_config = os.path.join(app_path, 'config.yaml')

__doc__ = '''edgy_crits.py: bidirectional synchronization between Soltra Edge and MITRE CRITs

Usage:
    edgy_crits.py [--config=CONFIG] --sync-crits-to-edge --source=SOURCE --destination=DESTINATION
    edgy_crits.py [--config=CONFIG] --sync-edge-to-crits --source=SOURCE --destination=DESTINATION

    edgy_crits.py --help
    edgy_crits.py --version


Options:
    -c CONFIG --config=CONFIG         Specify config file to use [default: %s].
    -h --help                         Show this screen.
    -V --version                      Show version.
    SOURCE...                         Specify host defined in config.yaml
    DESTINATION...                    Specify host defined in config.yaml

Please report bugs to support@soltra.com
''' % (default_config)


def main():
    args = docopt(__doc__, version=__version__)
    config = util_.parse_config(args['--config'])
    config['config_file'] = args['--config']
    logger = log_.setup_logging(config)
    config['logger'] = logger
    db = db_.DB(config)
    config['db'] = db
    config['daemon']['app_path'] = app_path
    if args['--sync-crits-to-edge']:
        if args['--source'] in config['crits']['sites'].keys() and args['--destination'] in config['edge']['sites'].keys():
            logger.info('initiating crits=>edge sync between %s and %s' % (args['--source'], args['--destination']))
            crits2edge(config, args['--source'], args['--destination'])
    elif args['--sync-edge-to-crits']:
        if args['--source'] in config['edge']['sites'].keys() and args['--destination'] in config['crits']['sites'].keys():
            logger.info('initiating edge=>crits sync between %s and %s' % (args['--source'], args['--destination']))
            edge2crits(config, args['--source'], args['--destination'])


if __name__ == '__main__':
    main()
