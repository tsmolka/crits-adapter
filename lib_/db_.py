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

# rough model
# =====
# sync_status:
#     crits_to_edge:
#     last_sync_timestamp: 2015-01-06 14:03:00
#     ids:
#             crits_id
#                       corresponding_edge_id
#                       created:
#     modified:
#     edge_to_crits:
#     last_sync_timestamp: 2015-01-06 14:03:00
#     ids:
#             crits_id
#                       corresponding_edge_id
#                       created:
#     modified:
    


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


    def get_last_sync(self, source, destination, direction):
        try:
            if self.collection.find({'source': source, 'destination': destination, 'direction': direction}).count():
                doc = self.collection.find_one({'source': source, 'destination': destination, 'direction': direction})
                return(doc['timestamp'])
            else:
                return(util_.epoch_start())
        except ConnectionFailure as e:
            self.logger.error('mongodb connection failed - exiting...')
            self.logger.exception(e)
            exit()


    def set_last_sync(self, source, destination, direction, timestamp):
        try:
            if self.collection.find({'source': source, 'destination': destination, 'direction': direction}).count():
                doc = self.collection.find_one({'source': source, 'destination': destination, 'direction': direction})
                self.collection.update(doc, {'$set': {'timestamp': timestamp}})
            else:
                self.collection.insert({'source': source, 'destination': destination, 'direction': direction, 'timestamp': timestamp})
        except ConnectionFailure as e:
            self.logger.error('mongodb connection failed - exiting...')
            self.logger.exception(e)
            exit()
        

