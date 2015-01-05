#!/usr/bin/env python2.7

from logbook import Logger, RotatingFileHandler
import os

def setup_logging(config):
    log_file = os.path.join(config['daemon']['app_path'], config['daemon']['log']['file'])
    log_handler = RotatingFileHandler(log_file, max_size=config['daemon']['log']['rotate_size'], backup_count=config['daemon']['log']['rotate_count'])
    log_handler.push_application()
    log = Logger('edgy_crits')
    return log
