#!/usr/bin/env python

from logbook import Logger, FileHandler

def setup_logging(config):
    log_handler = FileHandler(config['daemon']['log'])
    log_handler.push_application()
    log = Logger('edgy_crits')
    return log
