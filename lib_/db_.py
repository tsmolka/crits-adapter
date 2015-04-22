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


from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from cybox.core.observable import ObservableComposition
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
            {'type_': 'unresolved_crits_relationship',
             'src': src,
             'dest': dest,
             'edge_observable_id': edge_id}
        return(self.collection.find_one(query))

    def get_pending_crits_links(self, src, dest):
        query = \
            {'type_': 'unresolved_crits_relationship',
             'src': src,
             'dest': dest}
        return(self.collection.find(query))

    def set_pending_crits_link(self, src, dest, rhs_id=None,
                               lhs_id=None):
        # both rhs and lhs need to be _crits_ objects however we need
        # to support the fact that we have no way of determining an
        # object's crits id until it has been inboxed (ie, this cannot
        # be statically specified on the cli) nor can we control the
        # order in which edge objects come to us in a taxii feed...
        query = {'type_': 'unresolved_crits_relationship',
                 'src': src,
                 'dest': dest,
                 'rhs_id': rhs_id,
                 'lhs_id': lhs_id}
        self.collection.insert(query)

    def resolve_crits_link(self, src, dest, rhs_id=None,
                           lhs_id=None):
        # purge the resolved link...
        query = {'type_': 'unresolved_crits_relationship',
                 'src': src,
                 'dest': dest,
                 'rhs_id': rhs_id,
                 'lhs_id': lhs_id}
        self.collection.remove(query)


    def store_obs_comp(self, src, dest, obs_id=None,
                                     obs_comp=None):
        obs_json = obs_comp.to_json()
        query = {'type_': 'obs_comp',
                 'src': src,
                 'dest': dest,
                 'obs_id': obs_id,
                 'obs_comp': obs_json}
        self.collection.insert(query)

    def get_obs_comp(self, src, dest, obs_id=None):
        query = {'type_': 'obs_comp',
                 'src': src,
                 'dest': dest,
                 'obs_id': obs_id}
        doc = self.collection.find_one(query)
        if doc:
            if 'obs_comp' in doc.keys():
                obs_comp = \
                    ObservableComposition.from_json(doc['obs_comp'])
                return(obs_comp)
        else:
            return(None)
