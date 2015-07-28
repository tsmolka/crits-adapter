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
    'unsupported_object_error':
    'unsupported {type_} object type {obj_type} (id: {id_})',
    'obj_convert_error':
    '{src_type} {src_obj} (id: {id_}) could not be converted to {dest_type} {dest_obj}',
    'obj_inbox_error':
    'error inboxing {src_type} object (id: {id_}) to {dest_type}',
    'obj_inbox_success':
    '{src_type} object (id: {id_}) was successfully inboxed to {dest_type}',
    'polling_error':
    'unhandled {type_} polling error! {error}',
    'open_session': 'initiating {type_} connection to {host}',
    'inbox_error': '{type_} inboxing to {host} failed ({msg})',
    'inbox_success': '{type_} inboxing to {host} successful',
    'start_sync': 'syncing new {type_} data since {last_run} between {src} and {dest}',
    'saving_state': 'saving state until next run {next_run}',
    'obs_comp_dereference_error':
    'unable to dereference observable composition for stix indicator {id_}',
    'no_pending_crits_relationships':
    'no pending crits relationships to be processed at this time',
    'incoming_tally': '{count} {type_} objects to be synced from {src} to {dest}',
    'processed_tally': '{count} {type_} objects successfully synced from {src} to {dest}',
    'failed_tally': '{count} {type_} objects could not be synced from {src} to {dest}',
    'object_already_ingested': '{src_type} object id {src_id} (from {src})'
                                       'already in {dest_type} ({dest}) as {dest_id}'
    }
