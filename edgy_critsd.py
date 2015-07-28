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
from lib import util, log, db
import signal

__version__ = '0.3'
app_path = os.path.split(os.path.abspath(__file__))[0]
default_config = os.path.join(app_path, 'config.yaml')
__doc__ = '''edgy_critsd.py: a daemon to drive edgy_crits

Usage:
    edgy_critsd.py start [--config=CONFIG]
    edgy_critsd.py stop [--config=CONFIG]
    edgy_critsd.py restart [--config=CONFIG]
    edgy_critsd.py status [--config=CONFIG]

    edgy_critsd.py --help
    edgy_critsd.py --version


Options:
    -c CONFIG --config=CONFIG         Specify config file to use [default: %s].
    -h --help                         Show this screen.
    -V --version                      Show version.

Please report bugs to support@soltra.com
''' % (default_config)


def main():
    args = docopt(__doc__, version=__version__)
    config = util.parse_config(args['--config'])
    config['config_file'] = args['--config']
    config['daemon']['app_path'] = app_path
    logger = log.setup_logging(config)
    config['logger'] = logger
    my_db = db.DB(config)
    config['db'] = my_db
    daemon = util.Daemon(config)
    if args['start']:
        logger.info('edgy_critsd starting...')
        signal.signal(signal.SIGTERM, util.signal_handler)
        daemon.start()
    elif args['stop']:
        logger.info('edgy_critsd stopping...')
        daemon.stop()
    elif args['restart']:
        logger.info('edgy_critsd restarting...')
        daemon.restart()

if __name__ == '__main__':
    main()
