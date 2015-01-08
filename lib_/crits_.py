#!/usr/bin/env python2.7

from copy import deepcopy
from cybox.utils import Namespace
from cybox.utils import set_id_namespace as set_cybox_id_namespace
from cybox.utils import IDGenerator, set_id_method
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.file_object import File
from cybox.core.observable import Observable
from cybox.core import Observables
from cybox.common import Hash
from cybox.objects.email_message_object import EmailMessage, EmailHeader
from stix.core import STIXPackage, STIXHeader
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.indicator import Indicator

from stix.utils import set_id_namespace as set_stix_id_namespace
import util_
import edge_
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


def crits_poll(config, target, endpoint, id_=None):
    '''pull data from crits via api, return json as a dict'''
    url = crits_url(config, target)
    if config['crits']['sites'][target]['api']['allow_self_signed']:
        requests.packages.urllib3.disable_warnings()
    data = {'api_key'              : config['crits']['sites'][target]['api']['key'],
            'username'             : config['crits']['sites'][target]['api']['user'],}
            # 'c-releasability.name' : config['crits']['sites'][target]['api']['source']}
    if config['crits']['sites'][target]['api']['ssl']:
        r = requests.get(url + endpoint + '/' + id_ + '/', params=data, verify=not config['crits']['sites'][target]['api']['allow_self_signed'])
    else:
        r = requests.get(url + endpoint + '/' + id_ + '/', params=data)
    json_output = r.json()
    success = True if r.status_code == (200 or 201) else False
    if success:
        id_ = json_output[u'_id']
        del json_output[u'_id']
    return(id_, json_output)


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


def stix_pkg(config, source, endpoint, payload, title='random test data', description='random test data', package_intents='Indicators - Watchlist', tlp_color='WHITE'):
    '''package observables'''
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
    if isinstance(payload, Observable):
        stix_package.add_observable(payload)
    elif isinstance(payload, Indicator):
        stix_package.add_indicator(payload)
    return(stix_package)


def json2cybox(config, source, endpoint, json_):
    set_id_method(IDGenerator.METHOD_UUID)
    set_cybox_id_namespace(Namespace(config['edge']['sites'][source]['stix']['xmlns_url'], config['edge']['sites'][source]['stix']['xmlns_name']))
    if endpoint == 'ips':
        crits_types = {'Address - cidr': 'cidr', \
                       'Address - ipv4-addr': 'ipv4-addr', \
                       'Address - ipv4-net': 'ipv4-net', \
                       'Address - ipv4-net-mask': 'ipv4-netmask', \
                       'Address - ipv6-addr': 'ipv6-addr', \
                       'Address - ipv6-net': 'ipv6-net', \
                       'Address - ipv6-net-mask': 'ipv6-netmask'}
        addr = Address(address_value=json_['ip'], category=crits_types[json_['type']])
        addr.condition = 'Equals'
        return(Observable(addr))
    elif endpoint == 'domains':
        domain = DomainName()
        domain.type_ = 'FQDN'
        domain.value = json_['domain']
        domain.condition = 'Equals'
        return(Observable(domain))
    elif endpoint == 'samples':
        crits_types = {'md5'    : 'MD5', \
                       'sha1'   : 'SHA1', \
                       'sha224' : 'SHA224', \
                       'sha256' : 'SHA256', \
                       'sha384' : 'SHA384', \
                       'sha512' : 'SHA512', \
                       'ssdeep' : 'SSDEEP'}
        file_object = File()
        file_object.file_name = json_['filename']
        for hash in crits_types.keys():
            if hash in json_:
                file_object.add_hash(Hash(json_[hash], type_=crits_types[hash]))
        for i in file_object.hashes:
                i.simple_hash_value.condition = "Equals"
        return(Observable(file_object))
    elif endpoint == 'emails':
        crits_types = {'subject': 'subject', 'to': 'to', 'cc': 'cc',
        'from_address': 'from_', 'sender': 'sender', 'date': 'date',
        'message_id': 'message_id', 'reply_to': 'reply_to',
        'boundary': 'boundary', 'x_mailer': 'x_mailer',
        'x_originating_ip': 'x_originating_ip'}
        email = EmailMessage()
        email.header = EmailHeader()
        for key in crits_types.keys():
            val = json_.get(key, None)
            if val:
                email.header.__setattr__(crits_types[key], val)
                email.header.__getattribute__(crits_types[key]).condition = 'Equals'
        return(Observable(email))
    else:
        config['logger'].error('unsupported crits object type %s!' % endpoint)
        return(None)


def crits2edge(config, source, destination, daemon=False):
    # check if (and when) we synced source and destination...
    now = util_.nowutcmin()
    timestamp = config['db'].get_last_sync(source=source, destination=destination, direction='edge').replace(tzinfo=pytz.utc)
    config['logger'].info('syncing new crits data since %s between %s and %s' % (str(timestamp), source, destination))
    cybox_endpoints = ['ips', 'domains', 'samples', 'emails']
    ids = dict()
    total_input = 0
    total_output = 0
    subtotal_input = {}
    subtotal_output = {}
    for endpoint in cybox_endpoints:
        ids[endpoint] = fetch_crits_object_ids(config, source, endpoint, timestamp)
        for id_ in ids[endpoint]:
            if config['db'].get_object_id(source, destination, 'edge', endpoint + ':' + str(id_)):
                if config['daemon']['debug']:
                    config['logger'].debug('crits object id %s already in system' % id_)
                ids[endpoint].remove(id_)
        subtotal_input[endpoint] = len(ids[endpoint])
        subtotal_output[endpoint] = 0
        total_input += len(ids[endpoint])
    config['logger'].info('%i (total) objects to be synced between %s (crits) and %s (edge)' % (total_input, source, destination))
    for endpoint in cybox_endpoints:
        config['logger'].info('%i %s objects to be synced between %s (crits) and %s (edge)' % (subtotal_input[endpoint], endpoint, source, destination))
        if not len(ids[endpoint]): continue
        else:
            for crits_id in ids[endpoint]:
                (id_, json_) = crits_poll(config, source, endpoint, crits_id,)
                observable = json2cybox(config, source, endpoint, json_)
                stix_ = stix_pkg(config, source, endpoint, observable)
                success = edge_.taxii_inbox(config, destination, stix_)
                if not success:
                    config['logger'].info('crits object %s could not be synced between %s (crits) and %s (edge)' % (crits_id, source, destination))
                else:
                    subtotal_input[endpoint] -= 1
                    total_input -= 1
                    subtotal_output[endpoint] += 1
                    total_output += 1
                    config['db'].set_object_id(source, destination, 'edge', endpoint + ':' + crits_id, observable.id_, util_.nowutcmin())
        config['logger'].info('%i %s objects successfully synced between %s (crits) and %s (edge)' % (subtotal_output[endpoint], endpoint, source, destination))
        if subtotal_output[endpoint] < subtotal_input[endpoint]:
            config['logger'].info('%i %s objects could not be synced between %s (crits) and %s (edge)' % (len(ids[endpoint]), endpoint, source, destination))
    config['logger'].info('%i (total) objects successfully synced between %s (crits) and %s (edge)' % (total_output, source, destination))
    if total_output < total_input:
        config['logger'].info('%i (total) objects could not be synced between %s (crits) and %s (edge)' % (total_input - total_output, source, destination))
    # save state to disk for next run...
    if config['daemon']['debug']:
        config['logger'].debug('saving state until next run [%s]' % str(now + datetime.timedelta(seconds=config['crits']['sites'][source]['api']['poll_interval'])))
    config['db'].set_last_sync(source=source, destination=destination, direction='edge', timestamp=now)


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
