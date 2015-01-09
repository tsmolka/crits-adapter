#!/usr/bin/env python2.7

import log_
import util_
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure


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
        self.user=config['daemon']['mongo']['user']
        self.password=config['daemon']['mongo']['pass']
        self.logger=config['logger']
        if self.user and self.password:
            self.url = 'mongodb://%s:%s@%s:%s' % (self.user,
                                                  self.password,
                                                  self.host,
                                                  self.port)
        else:
            self.url = 'mongodb://%s:%s' % (self.host,
                                            self.port)
        try:
            self.logger.info('initializing mongodb connection...')
            self.client = MongoClient(self.url)
        except ConnectionFailure as e:
            self.logger.error('mongodb connection failed - exiting...')
            self.logger.exception(e)
            exit()
        self.db = self.client[config['daemon']['mongo']['db']]
        self.collection = self.db[config['daemon']['mongo']['collection']]
        self.logger.info('updating mongodb indices...')
        self.collection.ensure_index('source')
        self.collection.ensure_index('destination')
        self.collection.ensure_index('crits_id')
        self.collection.ensure_index('edge_id')


    def get_last_sync(self, source, destination, direction):
        try:
            doc = self.collection.find_one({'source': source, 'destination': destination, 'direction': direction})
            if doc and 'timestamp' in doc.keys():
                return(doc['timestamp'])
            else:
                return(util_.epoch_start())
        except ConnectionFailure as e:
            self.logger.error('mongodb connection failed - exiting...')
            self.logger.exception(e)
            exit()


    def set_last_sync(self, source, destination, direction, timestamp):
        try:
            doc = self.collection.find_one({'source': source, 'destination': destination, 'direction': direction})
            if doc:
                self.collection.update(doc, {'$set': {'timestamp': timestamp}})
            else:
                self.collection.insert({'source': source, 'destination': destination, 'direction': direction, 'timestamp': timestamp})
        except ConnectionFailure as e:
            self.logger.error('mongodb connection failed - exiting...')
            self.logger.exception(e)
            exit()
        

    def get_object_id(self, source, destination, direction, id_):
        try:
            query = {'source': source, 'destination': destination}
            if direction == 'edge':
                query['crits_id'] = id_
            else:
                query['edge_id'] = id_
            doc = self.collection.find_one(query)
            if doc:
                return(doc)
            else:
                return None
        except ConnectionFailure as e:
            self.logger.error('mongodb connection failed - exiting...')
            self.logger.exception(e)
            exit()


    def set_object_id(self, source, destination, direction, source_id, dest_id, timestamp):
        try:
            query = {'source': source, 'destination': destination, 'direction': direction}
            if direction == 'edge':
                query['crits_id'] = source_id
            else:
                query['edge_id'] = source_id
            doc = self.get_object_id(source, destination, direction, source_id)
            if doc:
                self.collection.update(doc, {'$set': {'modified': timestamp}})
            else:
                if direction == 'edge':
                    query['edge_id'] = dest_id
                else:
                    query['crits_id'] = dest_id
                query['created'] = util_.nowutcmin()
                query['modified'] = query['created']
                self.collection.insert(query)
        except ConnectionFailure as e:
            self.logger.error('mongodb connection failed - exiting...')
            self.logger.exception(e)
            exit()
