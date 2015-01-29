#!/usr/bin/env python2.7

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import log_
import pytz
import util_


def get_db(config):
    db = mongoengine.connect(config['daemon']['mongo']['db'],
                             host=config['daemon']['mongo']['host'],
                             port=config['daemon']['mongo']['port'],
                             username=config['daemon']['mongo']['user'],
                             password=config['daemon']['mongo']['pass'])
    return(db)


class DB(object):
    def __init__(self, config):
        self.host = config['daemon']['mongo']['host']
        self.port = config['daemon']['mongo']['port']
        self.user = config['daemon']['mongo']['user']
        self.password = config['daemon']['mongo']['pass']
        self.logger = config['logger']
        if self.user and self.password:
            self.url = 'mongodb://%s:%s@%s:%s' % (self.user,
                                                  self.password,
                                                  self.host,
                                                  self.port)
        else:
            self.url = 'mongodb://%s:%s' % (self.host,
                                            self.port)
        self.logger.info('initializing mongodb connection...')
        self.client = MongoClient(self.url)
        self.db = self.client[config['daemon']['mongo']['db']]
        self.collection = self.db[config['daemon']['mongo']['collection']]
        self.logger.info('updating mongodb indices...')
        self.collection.ensure_index('src')
        self.collection.ensure_index('dest')
        self.collection.ensure_index('crits_id')
        self.collection.ensure_index('edge_id')

    def get_last_sync(self, src, dest, direction=None,):
        doc = self.collection.find_one({'src': src,
                                        'dest': dest,
                                        'direction': direction})
        if doc and 'timestamp' in doc.keys():
            return(doc['timestamp'].replace(tzinfo=pytz.utc))
        else:
            return(util_.epoch_start().replace(tzinfo=pytz.utc))

    def set_last_sync(self, src, dest, direction=None,
                      timestamp=None):
        doc = self.collection.find_one({'src': src,
                                        'dest': dest,
                                        'direction': direction})
        if doc:
            self.collection.update(doc, {'$set': {'timestamp': timestamp}})
        else:
            self.collection.insert({'src': src,
                                    'dest': dest,
                                    'direction': direction,
                                    'timestamp': timestamp})

    def get_object_id(self, src, dest, crits_id=None, edge_id=None):
        query = {'src': src, 'dest': dest}
        if crits_id:
            query['crits_id'] = crits_id
        if edge_id:
            query['edge_id'] = edge_id
        doc = self.collection.find_one(query)
        if doc:
            return(doc)
        else:
            return None

    def set_object_id(self, src, dest, crits_id=None, edge_id=None):
        timestamp=util_.nowutc()
        query = {'src': src, 'dest': dest,
                 'crits_id': crits_id, 'edge_id': edge_id}
        doc = self.get_object_id(src, dest, crits_id=crits_id, edge_id=edge_id)
        if doc:
            # there's already a crits-edge mapping so just update
            # the timestamp
            self.collection.update(doc, {'$set': {'modified': timestamp}})
        else:
            # insert a new mapping
            query['created'] = timestamp
            query['modified'] = timestamp
            self.collection.insert(query)

    def get_pending_crits_link(self, src, dest, edge_id=None):
        query = \
            {'unresolved_crits_relationship':
             {'src': src,
              'dest': dest,
              'edge_observable_id': edge_id}}
        return(self.collection.find_one(query))

    def get_pending_crits_links(self, src, dest):
        query = \
            {'unresolved_crits_relationship':
             {'src': src,
              'dest': dest}}
        return(self.collection.find(query))

    def set_pending_crits_link(self, src, dest, crits_id=None,
                               edge_id=None):
        query = {'unresolved_crits_relationship':
                 {'src': src,
                  'dest': dest,
                  'crits_indicator_id': crits_id,
                  'edge_observable_id': edge_id}}
        self.collection.insert(query)

    def resolve_crits_link(self, src, dest, crits_id=None,
                           edge_id=None):
        query = {'unresolved_crits_relationship':
                 {'src': src,
                  'dest': dest,
                  'crits_indicator_id': crits_id,
                  'edge_observable_id': edge_id}}
        self.collection.remove(query)

