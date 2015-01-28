#!/usr/bin/env python2.7


from docopt import docopt
import os.path
from sys import path as python_path
python_path.append('./lib_')
from crits_ import crits2edge
from edge_ import edge2crits
import db_
import log_
import util_


__version__ = '0.2'
app_path = os.path.split(os.path.abspath(__file__))[0]
default_config = os.path.join(app_path, 'config.yaml')

__doc__ = '''edgy_crits.py: bidirectional synch between Soltra Edge and CRITs

Usage:
    edgy_crits.py [--config=CONFIG] --c2e --src=SRC --dest=DEST
    edgy_crits.py [--config=CONFIG] --e2c --src=SRC --dest=DEST

    edgy_crits.py --help
    edgy_crits.py --version


Options:
    -c CONFIG --config=CONFIG         Specify config file to use [default: %s].
    -h --help                         Show this screen.
    -V --version                      Show version.
    SRC...                            Specify host defined in config.yaml
    DEST...                           Specify host defined in config.yaml

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
    if args['--c2e']:
        if args['--src'] in config['crits']['sites'].keys() \
           and args['--dest'] in config['edge']['sites'].keys():
            logger.info('initiating crits=>edge sync between %s and %s'
                        % (args['--src'], args['--dest']))
            crits2edge(config, args['--src'], args['--dest'])
    elif args['--e2c']:
        if args['--src'] in config['edge']['sites'].keys() and \
           args['--dest'] in config['crits']['sites'].keys():
            logger.info('initiating edge=>crits sync between %s and %s'
                        % (args['--src'], args['--dest']))
            edge2crits(config, args['--src'], args['--dest'])


if __name__ == '__main__':
    main()
