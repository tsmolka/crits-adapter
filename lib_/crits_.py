#!/usr/bin/env python2.7

from copy import deepcopy
from cybox.common import Hash
from cybox.core import Observables
from cybox.core.observable import Observable, ObservableComposition
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.email_message_object import EmailMessage, EmailHeader
from cybox.objects.file_object import File
from cybox.utils import IDGenerator, set_id_method
from cybox.utils import Namespace
from cybox.utils import set_id_namespace as set_cybox_id_namespace
from stix.core import STIXPackage, STIXHeader
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.indicator import Indicator
from stix.utils import set_id_namespace as set_stix_id_namespace
import datetime
import edge_
import json
import pytz
import requests
import util_
import yaml
import sys


def crits_url(config, target):
    '''assemble base url for crits api'''
    url = str()
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
    allow_self_signed = \
        config['crits']['sites'][target]['api']['allow_self_signed']
    if allow_self_signed:
        requests.packages.urllib3.disable_warnings()
    data = {'api_key': config['crits']['sites'][target]['api']['key'],
            'username': config['crits']['sites'][target]['api']['user']}
    if config['crits']['sites'][source]['api']['use_releasability']:
        data.update({'c-releasability.name':
                     config['crits']['sites'][target]['api']['source']})
    if config['crits']['sites'][target]['api']['ssl']:
        r = requests.get(url + endpoint + '/' + id_ + '/',
                         params=data,
                         verify=not allow_self_signed)
    else:
        r = requests.get(url + endpoint + '/' + id_ + '/', params=data)
    json_output = r.json()
    success = r.status_code in (200, 201)
    if success:
        id_ = json_output[u'_id']
        del json_output[u'_id']
    return(id_, json_output)


def crits_inbox(config, target, endpoint, json):
    '''upload data to crits via api, return object id if successful'''
    url = crits_url(config, target)
    allow_self_signed = \
        config['crits']['sites'][target]['api']['allow_self_signed']
    if allow_self_signed:
        requests.packages.urllib3.disable_warnings()
    data = {'api_key': config['crits']['sites'][target]['api']['key'],
            'username': config['crits']['sites'][target]['api']['user'],
            'source': config['crits']['sites'][target]['api']['source']}
    data.update(json)
    if config['crits']['sites'][target]['api']['ssl']:
        r = requests.post(url + endpoint + '/',
                          data=data,
                          verify=not allow_self_signed)
    else:
        r = requests.post(url + endpoint + '/', data=data)
    json_output = r.json()
    result_code = json_output[u'return_code']
    success = r.status_code in (200, 201) and result_code == 0
    id_ = json_output.get(u'id')
    return(id_, success)


def stix_pkg(config, source, endpoint, payload, title='random test data',
             description='random test data',
             package_intents='Indicators - Watchlist',
             tlp_color='WHITE'):
    '''package observables'''
    # setup the xmlns...
    xmlns_url = config['edge']['sites'][source]['stix']['xmlns_url']
    xmlns_name = config['edge']['sites'][source]['stix']['xmlns_name']
    set_stix_id_namespace({xmlns_url: xmlns_name})
    set_cybox_id_namespace(Namespace(xmlns_url, xmlns_name))
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


def json2stix_ind(config, source, destination, endpoint, json_):
    '''transform crits indicators into stix indicators with embedded
    cybox observable composition'''
    try:
        set_id_method(IDGenerator.METHOD_UUID)
        xmlns_url = config['edge']['sites'][source]['stix']['xmlns_url']
        xmlns_name = config['edge']['sites'][source]['stix']['xmlns_name']
        set_cybox_id_namespace(Namespace(xmlns_url, xmlns_name))
        if endpoint == 'indicators':
            endpoint_trans = {'Email': 'emails', 'IP': 'ips',
                              'Sample': 'samples', 'Domain': 'domains'}
            if json_['type'] != 'Reference':
                config['logger'].error('unsupported crits indicator type %s!'
                                       % json_['type'])
                return(None)
            indicator_ = Indicator()
            indicator_.title = json_['value']
            indicator_.confidence = json_['confidence']['rating'].capitalize()
            indicator_.add_indicator_type('Malware Artifacts')
            observable_composition_ = ObservableComposition()
            observable_composition_.operator = \
                indicator_.observable_composition_operator
            for r in json_['relationships']:
                if r['relationship'] != 'Contains':
                    config['logger'].error('unsupported crits indicator '
                                           'relationship type %s!'
                                           % r['relationship'])
                    return(None)
                doc = \
                    config['db'].get_object_id(source,
                                               destination,
                                               crits_id='%s:%s'
                                               % (endpoint_trans[r['type']],
                                                  r['value']))
                # TODO if missing, try to inject the corresponding observable?
                if not doc or not doc.get('edge_id', None):
                    config['logger'].error('cybox observable corresponding to '
                                           'crits indicator relationship %s '
                                           'could not be found!' % r['value'])
                    return(None)
                observable_ = Observable()
                observable_.idref = doc['edge_id']
                observable_composition_.add(observable_)
                indicator_.observable = Observable()
                indicator_.observable.observable_composition = \
                    observable_composition_
                return(indicator_)
        else:
            config['logger'].error('unsupported crits object type %s!'
                                   % endpoint)
            return(None)
    except:
        e = sys.exc_info()[0]
        config['logger'].error('unhandled error converting crits indicator '
                               'json to stix!')
        config['logger'].exception(e)
        return(None)


def json2cybox(config, source, endpoint, json_):
    '''transform crits observables into cybox'''
    try:
        set_id_method(IDGenerator.METHOD_UUID)
        xmlns_url = config['edge']['sites'][source]['stix']['xmlns_url']
        xmlns_name = config['edge']['sites'][source]['stix']['xmlns_name']
        set_cybox_id_namespace(Namespace(xmlns_url, xmlns_name))
        if endpoint == 'ips':
            crits_types = {'Address - cidr': 'cidr',
                           'Address - ipv4-addr': 'ipv4-addr',
                           'Address - ipv4-net': 'ipv4-net',
                           'Address - ipv4-net-mask': 'ipv4-netmask',
                           'Address - ipv6-addr': 'ipv6-addr',
                           'Address - ipv6-net': 'ipv6-net',
                           'Address - ipv6-net-mask': 'ipv6-netmask'}
            addr = Address(address_value=json_['ip'],
                           category=crits_types[json_['type']])
            addr.condition = 'Equals'
            return(Observable(addr))
        elif endpoint == 'domains':
            domain = DomainName()
            domain.type_ = 'FQDN'
            domain.value = json_['domain']
            domain.condition = 'Equals'
            return(Observable(domain))
        elif endpoint == 'samples':
            crits_types = {'md5': 'MD5',
                           'sha1': 'SHA1',
                           'sha224': 'SHA224',
                           'sha256': 'SHA256',
                           'sha384': 'SHA384',
                           'sha512': 'SHA512',
                           'ssdeep': 'SSDEEP'}
            file_object = File()
            file_object.file_name = json_['filename']
            for hash in crits_types.keys():
                if hash in json_:
                    file_object.add_hash(Hash(json_[hash],
                                              type_=crits_types[hash]))
            for i in file_object.hashes:
                i.simple_hash_value.condition = "Equals"
            return(Observable(file_object))
        elif endpoint == 'emails':
            crits_types = {'subject': 'subject', 'to': 'to', 'cc': 'cc',
                           'from_address': 'from_', 'sender': 'sender',
                           'date': 'date', 'message_id': 'message_id',
                           'reply_to': 'reply_to', 'boundary': 'boundary',
                           'x_mailer': 'x_mailer',
                           'x_originating_ip': 'x_originating_ip'}
            email = EmailMessage()
            email.header = EmailHeader()
            for k in crits_types.keys():
                val = json_.get(k, None)
                if val:
                    email.header.__setattr__(crits_types[k], val)
                    email.header.__getattribute__(crits_types[k]).condition = \
                        'Equals'
            return(Observable(email))
        else:
            config['logger'].error('unsupported crits object type %s!'
                                   % endpoint)
            return(None)
    except:
        e = sys.exc_info()[0]
        config['logger'].error('unhandled error converting crits observable '
                               'json to cybox!')
        config['logger'].exception(e)
        return(None)


def crits2edge(config, src, dest, daemon=False,
               now=None, last_run=None):
    # check if (and when) we synced source and destination...
    if not now:
        now = util_.nowutc()
    if not last_run:
        last_run = config['db'].get_last_sync(source=src,
                                              destination=dest,
                                              direction='crits2edge')
        last_run = last_run.replace(tzinfo=pytz.utc)
    config['logger'].info('syncing new crits data since %s between '
                          '%s and %s' % (str(last_run), src, dest))
    cybox_endpoints = ['ips', 'domains', 'samples', 'emails', 'indicators']
    ids = dict()
    total_input = 0
    total_output = 0
    subtotal_input = {}
    subtotal_output = {}
    for endpoint in cybox_endpoints:
        ids[endpoint] = fetch_crits_object_ids(config, src, endpoint, last_run)
        for id_ in ids[endpoint]:
            sync_state = config['db'].get_object_id(src, destination,
                                                    crits_id=endpoint + ':'
                                                    + str(id_))
            if sync_state:
                if sync_state.get('edge_id', None):
                    if config['daemon']['debug']:
                        config['logger'].debug('crits object id %s already '
                                               'in system' % id_)
                    ids[endpoint].remove(id_)
        subtotal_input[endpoint] = len(ids[endpoint])
        subtotal_output[endpoint] = 0
        total_input += len(ids[endpoint])
    if total_input > 0:
        config['logger'].info('%i (total) objects to be synced between '
                              '%s (crits) and %s (edge)'
                              % (total_input, src, destination))
    for endpoint in cybox_endpoints:
        if subtotal_input[endpoint] > 0:
            config['logger'].info('%i %s objects to be synced between '
                                  '%s (crits) and %s (edge)'
                                  % (subtotal_input[endpoint],
                                     endpoint, src, destination))
        if not len(ids[endpoint]):
            continue
        else:
            for crits_id in ids[endpoint]:
                (id_, json_) = crits_poll(config, src, endpoint, crits_id,)
                if endpoint == 'indicators':
                    indicator = json2stix_ind(config, src, destination,
                                              endpoint, json_)
                    if not indicator:
                        config['logger'].info('crits object %s could not be '
                                              'synced between %s (crits) '
                                              'and %s (edge)'
                                              % (crits_id, src, destination))
                        continue
                    stix_ = stix_pkg(config, src, endpoint, indicator)
                    if not stix_:
                        config['logger'].info('crits object %s could not be '
                                              'synced between '
                                              '%s (crits) and %s (edge)'
                                              % (crits_id, src, destination))
                        continue
                    success = edge_.taxii_inbox(config, destination, stix_)
                    if not success:
                        config['logger'].info('crits object %s could not be '
                                              'synced between %s (crits) '
                                              'and %s (edge)'
                                              % (crits_id, src, destination))
                        continue
                    else:
                        subtotal_input[endpoint] -= 1
                        total_input -= 1
                        subtotal_output[endpoint] += 1
                        total_output += 1
                        config['db'].set_object_id(src, destination,
                                                   edge_id=indicator.id_,
                                                   crits_id=endpoint + ':'
                                                   + crits_id,
                                                   timestamp=util_.nowutc())
                else:
                    observable = json2cybox(config, src, endpoint, json_)
                    if not observable:
                        config['logger'].info('crits object %s could not be '
                                              'synced between '
                                              '%s (crits) and %s (edge)'
                                              % (crits_id, src, destination))
                        continue
                    stix_ = stix_pkg(config, src, endpoint, observable)
                    if not stix_:
                        config['logger'].info('crits object %s could not be '
                                              'synced between '
                                              '%s (crits) and %s (edge)'
                                              % (crits_id, src, destination))
                        continue
                    success = edge_.taxii_inbox(config, destination, stix_)
                    if not success:
                        config['logger'].info('crits object %s could not be '
                                              'synced between '
                                              '%s (crits) and %s (edge)'
                                              % (crits_id, src, destination))
                        continue
                    else:
                        subtotal_input[endpoint] -= 1
                        total_input -= 1
                        subtotal_output[endpoint] += 1
                        total_output += 1
                        config['db'].set_object_id(src, destination,
                                                   edge_id=observable.id_,
                                                   crits_id=endpoint + ':'
                                                   + crits_id,
                                                   timestamp=util_.nowutc())
        if subtotal_output[endpoint] > 0:
            config['logger'].info('%i %s objects successfully synced between '
                                  '%s (crits) and %s (edge)'
                                  % (subtotal_output[endpoint],
                                     endpoint, src, destination))
        if subtotal_output[endpoint] < subtotal_input[endpoint]:
            config['logger'].info('%i %s objects could not be synced '
                                  'between %s (crits) and %s (edge)'
                                  % (len(ids[endpoint]), endpoint,
                                     src, destination))
    if total_output > 0:
        config['logger'].info('%i (total) objects successfully synced '
                              'between %s (crits) and %s (edge)'
                              % (total_output, src, destination))
    if total_output < total_input:
        config['logger'].info('%i (total) objects could not be synced '
                              'between %s (crits) and %s (edge)'
                              % (total_input - total_output, src, destination))
    # save state to disk for next run...
    if config['daemon']['debug']:
        poll_interval = config['crits']['sites'][src]['api']['poll_interval']
        config['logger'].debug('saving state until next run [%s]'
                               % str(now +
                                     datetime.timedelta(
                                         seconds=poll_interval)))
    if not daemon:
        config['db'].set_last_sync(source=src, destination=destination,
                                   direction='crits2edge', timestamp=now)
        return(None)
    else:
        return(util_.nowutc())


def __fetch_crits_object_ids(config, target, endpoint, params):
    '''fetch all crits object ids from endpoint and return a list'''
    url = crits_url(config, target)
    allow_self_signed = \
        config['crits']['sites'][target]['api']['allow_self_signed']
    if allow_self_signed:
        requests.packages.urllib3.disable_warnings()
    if config['crits']['sites'][target]['api']['ssl']:
        r = requests.get(url + endpoint + '/', params=params,
                         verify=not allow_self_signed)
    else:
        r = requests.get(url + endpoint + '/', params=params)
    json_output = r.json()
    object_count = int(json_output[u'meta'][u'total_count'])
    max_results = config['crits']['sites'][target]['api']['max_results']
    if object_count > max_results:
        page_count = object_count // max_results
        if object_count % max_results > 0:
            page_count += 1
    else:
        page_count = 0
    object_ids = list()
    params['limit'] = max_results
    i = 0
    while i <= page_count:
        params['offset'] = i * max_results
        if config['crits']['sites'][target]['api']['ssl']:
            r = requests.get(url + endpoint + '/', params=params,
                             verify=not allow_self_signed)
        else:
            r = requests.get(url + endpoint + '/', params=params)
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
        params = {'api_key': config['crits']['sites'][target]['api']['key'],
                  'username': config['crits']['sites'][target]['api']['user'],
                  'limit': 1,  # just grabbing meta for total object count...
                  'c-created__gt': crits_timestamp,
                  'offset': 0}
        if config['crits']['sites'][source]['api']['use_releasability']:
            params.update({'c-releasability.name':
                           config['crits']['sites'][target]['api']['source']})
        object_ids.extend(__fetch_crits_object_ids(config, target,
                                                   endpoint, params))
        # TODO object updates have to be treated differently than creates...
        # # next, check for recently updated records...
        # params = {'api_key': config['crits']['sites'][target]['api']['key'],
        #           'username': config['crits']['sites'][target]['api']['user'],
        #           'limit': 1,  # just grabbing meta for total object count...
        #           'c-modified__gt': crits_timestamp,
        #           'c-releasability.name':
        #           config['crits']['sites'][target]['api']['source'],
        #           'offset': 0}
        # object_ids.update(__fetch_crits_object_ids(config, target,
        #                                            endpoint, params))
    else:
        params = {'api_key': config['crits']['sites'][target]['api']['key'],
                  'username': config['crits']['sites'][target]['api']['user'],
                  'limit': 1,  # just grabbing meta for total object count...
                  'offset': 0}
        if config['crits']['sites'][source]['api']['use_releasability']:
            params.update({'c-releasability.name':
                           config['crits']['sites'][target]['api']['source']})
        object_ids.extend(__fetch_crits_object_ids(config, target,
                                                   endpoint, params))
    return(object_ids)
