#!/usr/bin/env python

from copy import deepcopy
from cybox.utils import Namespace
from cybox.utils import set_id_namespace as set_cybox_id_namespace
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.file_object import File
from cybox.common import Hash
from cybox.objects.email_message_object import EmailMessage, EmailHeader
from stix.core import STIXPackage, STIXHeader
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.indicator import Indicator
from stix.utils import set_id_namespace as set_stix_id_namespace
import util
import edge
import json
import pytz
import requests
import yaml
import datetime


# TODO how to deal with deleted crits objects?
# TODO ensure that both source and destination are actually defined!
# TODO if we fail midway through an operation, what should we do with
#      the timestamp?
# TODO ensure that all timestamps are utc!
# TODO how to handle updates???


def crits_url(config, target):
    '''assemble base url for crits api'''
    url=str()
    if config['crits']['sites'][target]['api']['ssl']:
        url += 'https://'
    else:
        url += 'http://'
    url += config['crits']['sites'][target]['host']
    url += ':' + str(config['crits']['sites'][target]['api']['port'])
    url += config['crits']['sites'][target]['api']['path']
    return(url)


def crits_poll(config, target, endpoint, object_ids=None):
    '''pull data from crits via api, return json as a dict'''
    url = crits_url(config, target)
    results = dict()
    if config['crits']['sites'][target]['api']['allow_self_signed']:
        requests.packages.urllib3.disable_warnings()
    data = {'api_key'              : config['crits']['sites'][target]['api']['key'],
            'username'             : config['crits']['sites'][target]['api']['user'],}
            # 'c-releasability.name' : config['crits']['sites'][target]['api']['source']}
    for id_ in object_ids:
        if config['crits']['sites'][target]['api']['ssl']:
            r = requests.get(url + endpoint + '/' + id_ + '/', params=data, verify=not config['crits']['sites'][target]['api']['allow_self_signed'])
        else:
            r = requests.get(url + endpoint + '/' + id_ + '/', params=data)
        json_output = r.json()
        success = True if r.status_code == (200 or 201) else False
        if success:
            id_ = json_output[u'_id']
            del json_output[u'_id']
            results[id_] = json_output
    return(results)


def crits_inbox(config, target, endpoint, json):
    '''upload data to crits via api, return object id if successful'''
    url = crits_url(config, target)
    if config['crits']['sites'][target]['api']['allow_self_signed']:
        requests.packages.urllib3.disable_warnings()
    data = {'api_key'  : config['crits']['sites'][target]['api']['key'],
            'username' : config['crits']['sites'][target]['api']['user'],
            'source'   : config['crits']['sites'][target]['api']['source']}
    data.update(json)
    if config['crits']['sites'][target]['api']['ssl']:
        r = requests.post(url + endpoint + '/' , data=data, verify=not config['crits']['sites'][target]['api']['allow_self_signed'])
    else:
        r = requests.post(url + endpoint + '/', data=data)
    json_output = r.json()
    result_code = json_output[u'return_code']
    success = True if r.status_code == (200 or 201) and result_code == 0 else False
    id_ = json_output[u'id'] if u'id' in json_output.keys() else None
    return(id_, success)


def json2stix(config, source, endpoint, json_, title='random test data', description='random test data', package_intents='Indicators - Watchlist', tlp_color='WHITE'):
    '''generate stix data from crits json'''
    # setup the xmlns...
    set_stix_id_namespace({config['edge']['sites'][source]['stix']['xmlns_url']: config['edge']['sites'][source]['stix']['xmlns_name']})
    set_cybox_id_namespace(Namespace(config['edge']['sites'][source]['stix']['xmlns_url'], config['edge']['sites'][source]['stix']['xmlns_name']))
    # construct a stix package...
    stix_package = STIXPackage()
    stix_header = STIXHeader()
    stix_header.title = title
    stix_header.description = description
    stix_header.package_intents = package_intents
    marking = MarkingSpecification()
    marking.controlled_structure = '../../../../descendant-or-self::node()'
    tlp_marking = TLPMarkingStructure()
    tlp_marking.color = tlp_color
    marking.marking_structures.append(tlp_marking)
    stix_package.stix_header = stix_header
    stix_package.stix_header.handling = Marking()
    stix_package.stix_header.handling.add_marking(marking)
    if endpoint == 'ips':
        crits_types = {'Address - cidr': 'cidr', \
                       'Address - ipv4-addr': 'ipv4-addr', \
                       'Address - ipv4-net': 'ipv4-net', \
                       'Address - ipv4-net-mask': 'ipv4-netmask', \
                       'Address - ipv6-addr': 'ipv6-addr', \
                       'Address - ipv6-net': 'ipv6-net', \
                       'Address - ipv6-net-mask': 'ipv6-netmask'}
        for i in json_.keys():
            indicator = Indicator(title='IP Address for known C2 Channel')
            indicator.add_indicator_type('IP Watchlist')
            # import pudb; pu.db
            addr = Address(address_value=json_[i]['ip'], category=crits_types[json_[i]['type']])
            addr.condition = 'Equals'
            indicator.add_observable(addr)
            stix_package.add_indicator(indicator)
    elif endpoint == 'domains':
        for i in json_.keys():
            indicator = Indicator(title='A Very Bad [tm] Domain')
            indicator.add_indicator_type('Domain Watchlist')
            domain = DomainName()
            domain.type_ = 'FQDN'
            domain.value = json_[i]['domain']
            domain.condition = 'Equals'
            indicator.add_observable(domain)
            stix_package.add_indicator(indicator)
    elif endpoint == 'samples':
        crits_types = {'md5'    : 'MD5', \
                       'sha1'   : 'SHA1', \
                       'sha224' : 'SHA224', \
                       'sha256' : 'SHA256', \
                       'sha384' : 'SHA384', \
                       'sha512' : 'SHA512', \
                       'ssdeep' : 'SSDEEP'}
        for i in json_.keys():
            indicator = Indicator(title='A Very Bad [tm] Filehash')
            indicator.add_indicator_type('File Hash Watchlist')
            file_object = File()
            file_object.file_name = json_[i]['filename']
            # import pudb; pu.db
            for hash in crits_types.keys():
                if hash in json_[i]:
                    file_object.add_hash(Hash(json_[i][hash], type_=crits_types[hash]))
            for i in file_object.hashes:
                i.simple_hash_value.condition = "Equals"
            indicator.add_observable(file_object)
            stix_package.add_indicator(indicator)
    elif endpoint == 'emails':
        crits_types = {'subject': 'subject', 'to': 'to', 'cc': 'cc',
        'from_address': 'from_', 'sender': 'sender', 'date': 'date',
        'message_id': 'message_id', 'reply_to': 'reply_to',
        'boundary': 'boundary', 'x_mailer': 'x_mailer',
        'x_originating_ip': 'x_originating_ip'}
        for i in json_.keys():
            email = EmailMessage()
            email.header = EmailHeader()
            for key in crits_types.keys():
                val = json_[i].get(key, None)
                if val:
                    email.header.__setattr__(crits_types[key], val)
                    email.header.__getattribute__(crits_types[key]).condition = 'Equals'
            indicator = Indicator(title='spam spam spam')
            indicator.add_indicator_type('Malicious E-mail')
            indicator.add_observable(email)
            stix_package.add_indicator(indicator)
    else:
        config['logger'].error('unsupported crits object type %s!' % endpoint)
        return(None)
    return(stix_package)


def crits2edge(config, source, destination, daemon=False):
    # check if (and when) we synced source and destination...
    state_key = source + '_to_' + destination
    now = util.nowutcmin()
    # make yaml play nice...
    if not isinstance(config['state'], dict):
        config['state'] = dict()
    if not state_key in config['state'].keys():
        config['state'][state_key] = dict()
    if not 'crits_to_edge' in config['state'][state_key].keys():
        config['state'][state_key]['crits_to_edge'] = dict()
    if 'timestamp' in config['state'][state_key]['crits_to_edge'].keys():
        timestamp = config['state'][state_key]['crits_to_edge']['timestamp'].replace(tzinfo=pytz.utc)
        config['logger'].info('syncing new crits data since %s between %s and %s' % (str(timestamp), source, destination))
    else:
        # looks like first sync...
        # ...so we'll want to poll all records...
        config['logger'].info('initial sync between %s and %s' % (source, destination))
        timestamp = util.epoch_start()
    endpoints = ['ips', 'domains', 'samples', 'emails']
    ids = dict()
    total_input = 0
    total_output = 0
    subtotal_input = {}
    subtotal_output = {}
    for endpoint in endpoints:
        ids[endpoint] = fetch_crits_object_ids(config, source, endpoint, timestamp)
        subtotal_input[endpoint] = len(ids[endpoint])
        subtotal_output[endpoint] = 0
        total_input += len(ids[endpoint])
    config['logger'].info('%i (total) objects to be synced between %s (crits) and %s (edge)' % (total_input, source, destination))
    for endpoint in endpoints:
        config['logger'].info('%i %s objects to be synced between %s (crits) and %s (edge)' % (subtotal_input[endpoint], endpoint, source, destination))
        if not len(ids[endpoint]): continue
        else:
            while len(ids[endpoint]) > 0:
                if len(ids[endpoint]) <= 100:
                    json_ = crits_poll(config, source, endpoint, ids[endpoint])
                    stix_ = json2stix(config, source, endpoint, json_)
                    success = edge.taxii_inbox(config, destination, stix_)
                    if not success:
                        config['logger'].info('%i %s objects could not be synced between %s (crits) and %s (edge)' % (len(ids[endpoint]), endpoint, source, destination))
                    else:
                        subtotal_input[endpoint] -= len(ids[endpoint])
                        total_input -= len(ids[endpoint])
                        subtotal_output[endpoint] += len(ids[endpoint])
                        total_output += len(ids[endpoint])
                        config['logger'].info('%i %s objects successfully synced between %s (crits) and %s (edge)' % (subtotal_output[endpoint], endpoint, source, destination))
                        if subtotal_output[endpoint] < subtotal_input[endpoint]:
                            config['logger'].info('%i %s objects could not be synced between %s (crits) and %s (edge)' % (len(ids[endpoint]), endpoint, source, destination))
                    ids[endpoint] = list()
                else:
                    json_ = crits_poll(config, source, endpoint, ids[endpoint][0:99])
                    stix_ = json2stix(config, source, endpoint, json_)
                    success = edge.taxii_inbox(config, destination, stix_)
                    if not success:
                        config['logger'].info('%i %s objects could not be synced between %s (crits) and %s (edge)' % (len(ids[endpoint][0:99]), endpoint, source, destination))
                    else:
                        subtotal_input[endpoint] -= len(ids[endpoint][0:99])
                        total_input -= len(ids[endpoint][0:99])
                        subtotal_output[endpoint] += len(ids[endpoint][0:99])
                        total_output += len(ids[endpoint][0:99])
                        config['logger'].info('%i %s objects successfully synced between %s (crits) and %s (edge)' % (subtotal_output[endpoint], endpoint, source, destination))
                        if subtotal_output[endpoint] < (subtotal_input[endpoint] - len(ids[endpoint][100:])):
                            config['logger'].info('%i %s objects could not be synced between %s (crits) and %s (edge)' % (subtotal_input[endpoint] - (subtotal_output[endpoint] - len(ids[endpoint][100:])), endpoint, source, destination))
                    ids[endpoint] = ids[endpoint][100:]
    config['logger'].info('%i (total) objects successfully synced between %s (crits) and %s (edge)' % (total_output, source, destination))
    if total_output < total_input:
        config['logger'].info('%i (total) objects could not be synced between %s (crits) and %s (edge)' % (total_input - total_output, source, destination))
    # save state to disk for next run...
    if config['daemon']['debug']:
        config['logger'].debug('saving state until next run [%s]' % str(now + datetime.timedelta(seconds=config['crits']['sites'][source]['api']['poll_interval'])))
    if not daemon:
        yaml_ = deepcopy(config)
        yaml_['state'][state_key]['crits_to_edge']['timestamp'] = now
        del yaml_['config_file']
        del yaml_['logger']
        file_ = file(config['config_file'], 'w')
        yaml.dump(yaml_, file_, default_flow_style=False)
        file_.close()
    else:
        config['state'][state_key]['crits_to_edge']['timestamp'] = now

def __fetch_crits_object_ids(config, target, endpoint, params):
    '''fetch all crits object ids from endpoint and return a list'''
    url = crits_url(config, target)
    if config['crits']['sites'][target]['api']['allow_self_signed']:
        requests.packages.urllib3.disable_warnings()
    if config['crits']['sites'][target]['api']['ssl']:
        r = requests.get(url + endpoint + '/' , params=params, verify=not config['crits']['sites'][target]['api']['allow_self_signed'])
    else:
        r = requests.get(url + endpoint + '/' , params=params)
    json_output = r.json()
    object_count = int(json_output[u'meta'][u'total_count'])
    if object_count > config['crits']['sites'][target]['api']['max_results']:
        page_count = object_count // config['crits']['sites'][target]['api']['max_results']
        if object_count % config['crits']['sites'][target]['api']['max_results'] > 0:
            page_count += 1
    else:
        page_count = 0
    object_ids = list()
    params['limit'] = config['crits']['sites'][target]['api']['max_results']
    i = 0
    while i <= page_count:
        params['offset'] = i * config['crits']['sites'][target]['api']['max_results']
        if config['crits']['sites'][target]['api']['ssl']:
            r = requests.get(url + endpoint + '/' , params=params, verify=not config['crits']['sites'][target]['api']['allow_self_signed'])
        else:
            r = requests.get(url + endpoint + '/' , params=params)
        json_output = r.json()
        for object_ in json_output[u'objects']:
            object_ids.append(object_[u'_id'].encode('ascii', 'ignore'))
        i += 1
    return(object_ids)


def fetch_crits_object_ids(config, target, endpoint, timestamp=None):
    '''fetch all crits object ids from endpoint and return a list'''
    object_ids = list()
    if timestamp:
        crits_timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')
        # first, check for newly created records...
        params = {'api_key'              : config['crits']['sites'][target]['api']['key'],
                  'username'             : config['crits']['sites'][target]['api']['user'],
                  'limit'                : 1, # just grabbing meta for total object count...
                  'c-created__gt'        : crits_timestamp,
                  # 'c-releasability.name' : config['crits']['sites'][target]['api']['source'],
                  'offset'               : 0}
        object_ids.extend(__fetch_crits_object_ids(config, target, endpoint, params))
        # TODO object updates have to be treated differently than creates...
        # # next, check for recently updated records...
        # params = {'api_key'              : config['crits']['sites'][target]['api']['key'],
        #           'username'             : config['crits']['sites'][target]['api']['user'],
        #           'limit'                : 1, # just grabbing meta for total object count...
        #           'c-modified__gt'       : crits_timestamp,
        #           'c-releasability.name' : config['crits']['sites'][target]['api']['source'],
        #           'offset'               : 0}
        # object_ids.update(__fetch_crits_object_ids(config, target, endpoint, params))
    else:
        params = {'api_key'              : config['crits']['sites'][target]['api']['key'],
                  'username'             : config['crits']['sites'][target]['api']['user'],
                  # 'c-releasability.name' : config['crits']['sites'][target]['api']['source'],
                  'limit'                : 1, # just grabbing meta for total object count...
                  'offset'               : 0}
        object_ids.extend(__fetch_crits_object_ids(config, target, endpoint, params))
    return(object_ids)


#
# crits api
# =========
#
# {"actoridentifiers":
#     {"list_endpoint": "/api/v1/actoridentifiers/",
#      "schema": "/api/v1/actoridentifiers/schema/"},
#  "actors":
#   {"list_endpoint": "/api/v1/actors/",
#    "schema": "/api/v1/actors/schema/"},
# "campaigns":
#   {"list_endpoint": "/api/v1/campaigns/",
#    "schema": "/api/v1/campaigns/schema/"},
# "certificates":
#   {"list_endpoint": "/api/v1/certificates/",
#    "schema": "/api/v1/certificates/schema/"},
# "domains":
#   {"list_endpoint": "/api/v1/domains/",
#    "schema": "/api/v1/domains/schema/"},
# "emails":
#   {"list_endpoint": "/api/v1/emails/",
#    "schema": "/api/v1/emails/schema/"},
# "events":
#   {"list_endpoint": "/api/v1/events/",
#    "schema": "/api/v1/events/schema/"},
# "indicator_activity":
#   {"list_endpoint": "/api/v1/indicator_activity/",
#    "schema": "/api/v1/indicator_activity/schema/"},
# "indicators":
#   {"list_endpoint": "/api/v1/indicators/",
#    "schema": "/api/v1/indicators/schema/"},
# "ips":
#   {"list_endpoint": "/api/v1/ips/",
#    "schema": "/api/v1/ips/schema/"},
# "objects":
#   {"list_endpoint": "/api/v1/objects/",
#    "schema": "/api/v1/objects/schema/"},
# "pcaps":
#   {"list_endpoint": "/api/v1/pcaps/",
#    "schema": "/api/v1/pcaps/schema/"},
# "raw_data":
#   {"list_endpoint": "/api/v1/raw_data/",
#    "schema": "/api/v1/raw_data/schema/"},
# "relationships":
#   {"list_endpoint": "/api/v1/relationships/",
#    "schema": "/api/v1/relationships/schema/"},
# "samples":
#   {"list_endpoint": "/api/v1/samples/",
#    "schema": "/api/v1/samples/schema/"},
# "screenshots":
#   {"list_endpoint": "/api/v1/screenshots/",
#    "schema": "/api/v1/screenshots/schema/"},
# "services":
#   {"list_endpoint": "/api/v1/services/",
#    "schema": "/api/v1/services/schema/"},
# "standards":
#   {"list_endpoint": "/api/v1/standards/",
#    "schema": "/api/v1/standards/schema/"},
# "targets":
#   {"list_endpoint": "/api/v1/targets/",
#    "schema": "/api/v1/targets/schema/"},
# "whois":
# {"list_endpoint": "/api/v1/whois/",
#  "schema": "/api/v1/whois/schema/"}}
