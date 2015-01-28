#!/usr/bin/env python2.7

from logbook import Logger, FileHandler, RotatingFileHandler
import os


def setup_logging(config):
    log_file = os.path.join(config['daemon']['app_path'],
                            config['daemon']['log']['file'])
    # if running in debug mode, disable log rotation because it makes
    # things confusing
    if config['daemon']['debug']:
        log_handler = FileHandler(log_file)
    else:
        max_size = config['daemon']['log']['rotate_size']
        backup_count = config['daemon']['log']['rotate_count']
        log_handler = RotatingFileHandler(log_file, max_size=max_size,
                                          backup_count=backup_count)
    log_handler.push_application()
    log = Logger('edgy_crits')
    return log
