#!/usr/bin/env python2.7


# Copyright 2015 Soltra Solutions, LLC

# Licensed under the Soltra License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.

# You may obtain a copy of the License at
# http://www.soltra.com/licenses/license-2.0.txt

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,

# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.

# See the License for the specific language governing permissions and
# limitations under the License.


from docopt import docopt
import os.path
from lib.crits import crits2edge
from lib.edge import edge2crits
from lib import db, log, util


__version__ = '0.3'
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
    config = util.parse_config(args['--config'])
    config['config_file'] = args['--config']
    logger = log.setup_logging(config)
    config['logger'] = logger
    my_db = db.DB(config)
    config['db'] = my_db
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
