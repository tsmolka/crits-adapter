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

log_messages = {
    'unsupported_stix_object_error':
    'unsupported stix object type {type_} (id: {id_})',
    'observable_convert_error':
    'cybox observable (id: {id_}) could not be converted to crits json',
    'crits_inbox_error':
    'error inboxing edge object (id: {id_}) to crits {endpoint} api endpoint',
    'crits_inbox_success':
    'edge object (id: {id_}) was successfully inboxed to crits '
    '{endpoint} api endpoint',
    'taxii_polling_error':
    'unhandled taxii polling error! {error}',
    'taxii_open_session': 'initiating taxii connection to {host}',
    'taxii_inbox_error': 'taxii inboxing to {host} failed! ({msg})',
    'taxii_inbox_success': 'taxii inboxing to {host} was successful',
    'start_sync': 'syncing new {type_} data since {last_run} between {src} and {dest}',
    'saving_state': 'saving state until next run {next_run}',
    'obs_comp_dereference_error':
    'unable to dereference observable composition for stix indicator {id_}',
    }
