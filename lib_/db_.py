#!/usr/bin/env python2.7

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import log_
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


    def get_last_sync(self, source, destination, direction=None,):
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


    def set_last_sync(self, source, destination, direction=None, timestamp=None):
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
        

    def get_object_id(self, source, destination, crits_id=None, edge_id=None):
        if crits_id and edge_id: return None
        try:
            query = {'source': source, 'destination': destination}
            if crits_id:
                query['crits_id'] = crits_id
            elif edge_id:
                query['edge_id'] = edge_id
            doc = self.collection.find_one(query)
            if doc:
                return(doc)
            else:
                return None
        except ConnectionFailure as e:
            self.logger.error('mongodb connection failed - exiting...')
            self.logger.exception(e)
            exit()


    def set_object_id(self, source, destination, crits_id=None, edge_id=None, timestamp=None):
        try:
            query = {'source': source, 'destination': destination}
            if crits_id:
                query['crits_id'] = crits_id
            elif edge_id:
                query['edge_id'] = edge_id
            doc = self.get_object_id(source, destination, crits_id=crits_id, edge_id=edge_id)
            if doc:
                # there's already a crits-edge mapping so just update the timestamp
                self.collection.update(doc, {'$set': {'modified': timestamp}})
            else:
                # insert a new mapping
                query['edge_id'] = edge_id
                query['crits_id'] = crits_id
                query['created'] = util_.nowutc()
                query['modified'] = query['created']
                self.collection.insert(query)
        except ConnectionFailure as e:
            self.logger.error('mongodb connection failed - exiting...')
            self.logger.exception(e)
            exit()

            
    def get_unresolved_crits_relationship(self, source, destination, edge_observable_id=None):
        try:
            query = {'unresolved_crits_relationship': {'source': source, 'destination': destination, 'edge_observable_id': edge_observable_id}}
            return(self.collection.find_one(query))
        except ConnectionFailure as e:
            self.logger.error('mongodb connection failed - exiting...')
            self.logger.exception(e)
            exit()

            
    def set_unresolved_crits_relationship(self, source, destination, crits_indicator_id=None, edge_observable_id=None):
        try:
            query = {'unresolved_crits_relationship': {'source': source, 'destination': destination, 'crits_indicator_id': crits_indicator_id, 'edge_observable_id': edge_observable_id}}
            self.collection.insert(query)
        except ConnectionFailure as e:
            self.logger.error('mongodb connection failed - exiting...')
            self.logger.exception(e)
            exit()


    def resolve_crits_relationship(self, source, destination, crits_indicator_id=None, edge_observable_id=None):
        try:
            query = {'unresolved_crits_relationship': {'source': source, 'destination': destination, 'crits_indicator_id': crits_indicator_id, 'edge_observable_id': edge_observable_id}}
            self.collection.remove(query)
        except ConnectionFailure as e:
            self.logger.error('mongodb connection failed - exiting...')
            self.logger.exception(e)
            exit()
            
