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
from stix.incident import Incident
from stix.common.related import RelatedIndicator, RelatedObservable, RelatedIncident
import datetime
import edge_
import json
import requests
import util_
import yaml
import sys
import log_


def crits_url(config, host):
    '''assemble base url for crits api'''
    url = str()
    if config['crits']['sites'][host]['api']['ssl']:
        url += 'https://'
    else:
        url += 'http://'
    url += config['crits']['sites'][host]['host']
    url += ':' + str(config['crits']['sites'][host]['api']['port'])
    url += config['crits']['sites'][host]['api']['path']
    return(url)


def crits_poll(config, src, endpoint, id_=None):
    '''pull data from crits via api, return json as a dict'''
    url = crits_url(config, src)
    attempt_certificate_validation = \
        config['crits']['sites'][src]['api']['attempt_certificate_validation']
    if attempt_certificate_validation:
        requests.packages.urllib3.disable_warnings()
    data = {'api_key': config['crits']['sites'][src]['api']['key'],
            'username': config['crits']['sites'][src]['api']['user']}
    if config['crits']['sites'][src]['api']['use_releasability']:
        data.update({'c-releasability.name':
                     config['crits']['sites'][src]['api']['source']})
    if config['crits']['sites'][src]['api']['ssl']:
        r = requests.get(url + endpoint + '/' + id_ + '/',
                         params=data,
                         verify=not attempt_certificate_validation)
    else:
        r = requests.get(url + endpoint + '/' + id_ + '/', params=data)
    json_output = r.json()
    success = r.status_code in (200, 201)
    if success:
        id_ = json_output[u'_id']
        del json_output[u'_id']
    return(id_, json_output)


def crits_inbox(config, dest, endpoint, json, src=None, edge_id=None):
    '''upload data to crits via api, return object id if successful'''
    if src:
        xmlns_name = config['edge']['sites'][src]['stix']['xmlns_name']
        if edge_id:
            # check whether this has already been ingested
            sync_state = config['db'].get_object_id(src, dest, edge_id=edge_id)
            if sync_state and sync_state.get('crits_id', None):
                if config['daemon']['debug']:
                    config['logger'].debug(
                        log_.log_messages['object_already_ingested'].format(
                            src_type='edge', src_id=edge_id, src=src, 
                            dest_type='crits', dest=dest, dest_id=sync_state['crits_id']))
                    return(sync_state['crits_id'], True)
    else:
        xmlns_name = config['crits']['sites'][dest]['api']['source']
    url = crits_url(config, dest)
    attempt_certificate_validation = \
        config['crits']['sites'][dest]['api']['attempt_certificate_validation']
    if attempt_certificate_validation:
        requests.packages.urllib3.disable_warnings()
    data = {'api_key': config['crits']['sites'][dest]['api']['key'],
            'username': config['crits']['sites'][dest]['api']['user'],
            'source': config['crits']['sites'][dest]['api']['source']}
    data.update(json)
    if config['crits']['sites'][dest]['api']['ssl']:
        r = requests.post(url + endpoint + '/',
                          data=data,
                          verify=not attempt_certificate_validation)
    else:
        r = requests.post(url + endpoint + '/', data=data)
    json_output = r.json()
    result_code = json_output[u'return_code']
    crits_id = None
    success = r.status_code in (200, 201) and result_code == 0 and 'id' in json_output.keys()
    if success:
        crits_id = json_output.get(u'id')
        if src and edge_id:
            # track the related crits/json ids (by src/dest)
            config['db'].set_object_id(src, dest, edge_id=edge_id,
                                       crits_id=(xmlns_name + ':' + 
                                                 endpoint + '-' + crits_id))
    return(crits_id, success)


def stix_pkg(config, src, endpoint, payload, title='random test data',
             description='random test data',
             package_intents='Indicators - Watchlist',
             tlp_color='WHITE'):
    '''package observables'''
    # setup the xmlns...
    xmlns_url = config['edge']['sites'][src]['stix']['xmlns_url']
    xmlns_name = config['edge']['sites'][src]['stix']['xmlns_name']
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
    elif isinstance(payload, Incident):
        stix_package.add_incident(payload)
    return(stix_package)


def json2indicator(config, src, dest, endpoint, json_, crits_id):
    '''transform crits indicators into stix indicators with embedded
    cybox observable composition'''
    try:
        set_id_method(IDGenerator.METHOD_UUID)
        xmlns_url = config['edge']['sites'][dest]['stix']['xmlns_url']
        xmlns_name = config['edge']['sites'][dest]['stix']['xmlns_name']
        set_cybox_id_namespace(Namespace(xmlns_url, xmlns_name))
        if endpoint == 'indicators':
            endpoint_trans = {'Email': 'emails', 'IP': 'ips',
                              'Sample': 'samples', 'Domain': 'domains', 
                              'Indicator': 'indicators', 'Event': 'events'}
            if json_['type'] not in ['Reference', 'Related_To']:
                config['logger'].error(
                    log_.log_messages['unsupported_object_error'].format(
                        type_='crits', obj_type='indicator type ' + json_['type'],
                        id_=crits_id))
                return(None)
            indicator_ = Indicator()
            indicator_.id = xmlns_name + ':indicator-' + crits_id
            indicator_.id_ = indicator_.id
            indicator_.title = json_['value']
            indicator_.confidence = json_['confidence']['rating'].capitalize()
            indicator_.add_indicator_type('Malware Artifacts')
            observable_composition_ = ObservableComposition()
            observable_composition_.operator = \
                indicator_.observable_composition_operator
            for r in json_['relationships']:
                if r['relationship'] not in ['Contains', 'Related_To']:
                    config['logger'].error(
                        log_.log_messages['unsupported_object_error'].format(
                            type_='crits', obj_type='indicator relationship type '
                            + r['relationship'], id_=crits_id))
                    continue
                if r['type'] in ['Sample', 'Email', 'IP', 'Sample', 'Domain']:
                    observable_ = Observable()
                    observable_.idref = xmlns_name + ':observable-' + r['value']
                    observable_composition_.add(observable_)
                elif r['type'] == 'Indicator':
                    related_indicator = RelatedIndicator(Indicator(idref=xmlns_name + ':indicator-' + r['value']))
                    indicator_.related_indicators.append(related_indicator)
                # stix indicators don't support related_incident :-(
                # elif r['type'] == 'Event':
                #     related_incident = RelatedIncident(Incident(idref=xmlns_name + ':incident-' + r['value']))
                #     indicator_.related_incidents.append(related_incident)
            indicator_.observable = Observable()
            indicator_.observable.observable_composition = \
                observable_composition_
            return(indicator_)
        else:
            config['logger'].error(
                log_.log_messages['unsupported_object_error'].format(
                    type_='crits', obj_type=endpoint, id_=crits_id))
            return(None)
    except:
        e = sys.exc_info()[0]
        config['logger'].error(log_.log_messages['obj_convert_error'].format(
            src_type='crits', src_obj='indicator', id_=crits_id,
            dest_type='stix', dest_obj='indicator'))
        config['logger'].exception(e)
        return(None)


def json2incident(config, src, dest, endpoint, json_, crits_id):
    '''transform crits events into stix incidents with related indicators'''
    try:
        set_id_method(IDGenerator.METHOD_UUID)
        xmlns_url = config['edge']['sites'][dest]['stix']['xmlns_url']
        xmlns_name = config['edge']['sites'][dest]['stix']['xmlns_name']
        set_cybox_id_namespace(Namespace(xmlns_url, xmlns_name))
        if endpoint == 'events':
            endpoint_trans = {'Email': 'emails', 'IP': 'ips',
                              'Sample': 'samples', 'Domain': 'domains', 
                              'Indicator': 'indicators'}
            status_trans = {'New': 'New', 'In Progress': 'Open',
                            'Analyzed': 'Closed', 'Deprecated': 'Rejected'}
            incident_ = Incident()
            incident_.id = xmlns_name + ':incident-' + crits_id
            incident_.id_ = incident_.id
            incident_.title = json_['title']
            incident_.description = json_['description']
            incident_.status = status_trans[json_['status']]
            # incident_.confidence = json_['confidence']['rating'].capitalize()
            for r in json_['relationships']:
                if r['relationship'] not in ['Contains', 'Related_To']:
                    config['logger'].error(
                        log_.log_messages['unsupported_object_error'].format(
                            type_='crits', obj_type='event relationship type '
                            + r['relationship'], id_=crits_id))
                    continue
                if r['type'] in ['Sample', 'Email', 'IP', 'Sample', 'Domain']:
                    related_observable = RelatedObservable(Observable(idref=xmlns_name + ':observable-' + r['value']))
                    incident_.related_observables.append(related_observable)
                elif r['type'] == 'Indicator':
                    related_indicator = RelatedIndicator(Indicator(idref=xmlns_name + ':indicator-' + r['value']))
                    incident_.related_indicators.append(related_indicator)
                elif r['type'] == 'Event':
                    related_incident = RelatedIncident(Incident(idref=xmlns_name + ':incident-' + r['value']))
                    incident_.related_incidents.append(related_incident)
            return(incident_)
        else:
            config['logger'].error(
                log_.log_messages['unsupported_object_error'].format(
                    type_='crits', obj_type=endpoint, id_=crits_id))
            return(None)
    except:
        e = sys.exc_info()[0]
        config['logger'].error(log_.log_messages['obj_convert_error'].format(
            src_type='crits', src_obj='event', id_=crits_id,
            dest_type='stix', dest_obj='incident'))
        config['logger'].exception(e)
        return(None)


def json2observable(config, src, dest, endpoint, json_, crits_id):
    # TODO split into smaller functions
    '''transform crits observables into cybox'''
    try:
        set_id_method(IDGenerator.METHOD_UUID)
        xmlns_url = config['edge']['sites'][dest]['stix']['xmlns_url']
        xmlns_name = config['edge']['sites'][dest]['stix']['xmlns_name']
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
            observable_ = Observable(addr)
        elif endpoint == 'domains':
            domain = DomainName()
            domain.type_ = 'FQDN'
            domain.value = json_['domain']
            domain.condition = 'Equals'
            observable_ = Observable(domain)
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
            observable_ = Observable(file_object)
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
            observable_ = Observable(email)
        else:
            config['logger'].error(
                log_.log_messages['unsupported_object_error'].format(
                    type_='crits', obj_type=endpoint, id_=crits_id))
            return(None)
        observable_.id = xmlns_name + ':observable-' + crits_id
        observable_.id_ = observable_.id
        return(observable_)
    except:
        e = sys.exc_info()[0]
        config['logger'].error(
            log_.log_messages['obj_convert_error'].format(
                src_type='crits', src_obj='observable', id_=crits_id,
                dest_type='cybox', dest_obj='observable'))
        config['logger'].exception(e)
        return(None)


def __fetch_crits_object_ids(config, src, endpoint, params):
    # TODO refactor this and merge with fetch_crits_object_ids() /
    #      split into smaller functions
    '''fetch all crits object ids from endpoint and return a list'''
    url = crits_url(config, src)
    attempt_certificate_validation = \
        config['crits']['sites'][src]['api']['attempt_certificate_validation']
    if attempt_certificate_validation:
        requests.packages.urllib3.disable_warnings()
    if config['crits']['sites'][src]['api']['ssl']:
        r = requests.get(url + endpoint + '/', params=params,
                         verify=not attempt_certificate_validation)
    else:
        r = requests.get(url + endpoint + '/', params=params)
    json_output = r.json()
    object_count = int(json_output[u'meta'][u'total_count'])
    max_results = config['crits']['sites'][src]['api']['max_results']
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
        if config['crits']['sites'][src]['api']['ssl']:
            r = requests.get(url + endpoint + '/', params=params,
                             verify=not attempt_certificate_validation)
        else:
            r = requests.get(url + endpoint + '/', params=params)
        json_output = r.json()
        for object_ in json_output[u'objects']:
            object_ids.append(object_[u'_id'].encode('ascii', 'ignore'))
        i += 1
    return(object_ids)


def fetch_crits_object_ids(config, src, endpoint, timestamp=None):
    '''fetch all crits object ids from endpoint and return a list'''
    object_ids = list()
    if timestamp:
        crits_timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')
        # first, check for newly created records...
        params = {'api_key': config['crits']['sites'][src]['api']['key'],
                  'username': config['crits']['sites'][src]['api']['user'],
                  'limit': 1,  # just grabbing meta for total object count...
                  'c-created__gt': crits_timestamp,
                  'offset': 0}
        if config['crits']['sites'][src]['api']['use_releasability']:
            params.update({'c-releasability.name':
                           config['crits']['sites'][src]['api']['source']})
        object_ids.extend(__fetch_crits_object_ids(config, src,
                                                   endpoint, params))
        # TODO object updates have to be treated differently than creates...
        # # next, check for recently updated records...
        # params = {'api_key': config['crits']['sites'][src]['api']['key'],
        #           'username': config['crits']['sites'][src]['api']['user'],
        #           'limit': 1,  # just grabbing meta for total object count...
        #           'c-modified__gt': crits_timestamp,
        #           'c-releasability.name':
        #           config['crits']['sites'][src]['api']['source'],
        #           'offset': 0}
        # object_ids.update(__fetch_crits_object_ids(config, src,
        #                                            endpoint, params))
    else:
        params = {'api_key': config['crits']['sites'][src]['api']['key'],
                  'username': config['crits']['sites'][src]['api']['user'],
                  'limit': 1,  # just grabbing meta for total object count...
                  'offset': 0}
        if config['crits']['sites'][src]['api']['use_releasability']:
            params.update({'c-releasability.name':
                           config['crits']['sites'][src]['api']['source']})
        object_ids.extend(__fetch_crits_object_ids(config, src,
                                                   endpoint, params))
    return(object_ids)


def crits2edge(config, src, dest, daemon=False,
               now=None, last_run=None):
    xmlns_name = config['edge']['sites'][dest]['stix']['xmlns_name']
    # check if (and when) we synced src and dest...
    if not now:
        now = util_.nowutc()
    if not last_run:
        last_run = config['db'].get_last_sync(src=src, dest=dest,
                                              direction='c2e')
    config['logger'].info(
        log_.log_messages['start_sync'].format(
            type_='crits', last_run=last_run, src=src, dest=dest))
    endpoints = ['ips', 'domains', 'samples', 'emails', 'indicators', 'events']
    # setup the tally counters
    config['crits_tally'] = dict()
    config['crits_tally']['all'] = {'incoming': 0, 'processed': 0}
    for endpoint in endpoints:
        config['crits_tally'][endpoint] = {'incoming': 0, 'processed': 0}
    ids = dict()
    for endpoint in endpoints:
        ids[endpoint] = fetch_crits_object_ids(config, src, endpoint, last_run)
        if not len(ids[endpoint]):
            continue
        else:
            for crits_id in ids[endpoint]:
                (id_, json_) = crits_poll(config, src, endpoint, crits_id,)
                if endpoint == 'indicators':
                    indicator = json2indicator(config, src, dest,
                                              endpoint, json_, id_)
                    config['crits_tally']['indicators']['incoming'] += 1
                    config['crits_tally']['all']['incoming'] += 1
                    if not indicator:
                        config['logger'].info(
                            log_.log_messages['obj_inbox_error'].format(
                                src_type='crits', id_=crits_id, dest_type='edge'))
                        continue
                    stix_ = stix_pkg(config, src, endpoint, indicator)
                    if not stix_:
                        config['logger'].info(
                            log_.log_messages['obj_inbox_error'].format(
                                src_type='crits', id_=crits_id, dest_type='edge'))
                        continue
                    success = edge_.taxii_inbox(config, dest, stix_, src=src,
                                                crits_id=endpoint + ':'
                                                + crits_id)
                    if not success:
                        config['logger'].info(
                            log_.log_messages['obj_inbox_error'].format(
                                src_type='crits', id_=crits_id, dest_type='edge'))
                        continue
                    else:
                        # track the related crits/json ids (by src/dest)
                        config['db'].set_object_id(src, dest,
                                                   edge_id=indicator.id_,
                                                   crits_id=(xmlns_name + ':' + 
                                                             endpoint + '-' + crits_id))
                        config['crits_tally']['indicators']['processed'] += 1
                        config['crits_tally']['all']['processed'] += 1
                elif endpoint == 'events':
                    incident = json2incident(config, src, dest,
                                              endpoint, json_, id_)
                    config['crits_tally']['events']['incoming'] += 1
                    config['crits_tally']['all']['incoming'] += 1
                    if not incident:
                        config['logger'].info(
                            log_.log_messages['obj_inbox_error'].format(
                                src_type='crits', id_=crits_id, dest_type='edge'))
                        continue
                    stix_ = stix_pkg(config, src, endpoint, incident)
                    if not stix_:
                        config['logger'].info(
                            log_.log_messages['obj_inbox_error'].format(
                                src_type='crits', id_=crits_id, dest_type='edge'))
                        continue
                    success = edge_.taxii_inbox(config, dest, stix_, src=src,
                                                crits_id=endpoint + ':'
                                                + crits_id)
                    if not success:
                        config['logger'].info(
                            log_.log_messages['obj_inbox_error'].format(
                                src_type='crits', id_=crits_id, dest_type='edge'))
                        continue
                    else:
                        # track the related crits/json ids (by src/dest)
                        config['db'].set_object_id(src, dest,
                                                   edge_id=incident.id_,
                                                   crits_id=(xmlns_name + ':' + 
                                                             endpoint + '-' + crits_id))
                        config['crits_tally']['events']['processed'] += 1
                        config['crits_tally']['all']['processed'] += 1
                else:
                    observable = json2observable(config, src, dest, endpoint, json_, crits_id)
                    config['crits_tally'][endpoint]['incoming'] += 1
                    config['crits_tally']['all']['incoming'] += 1
                    if not observable:
                        config['logger'].info(
                            log_.log_messages['obj_inbox_error'].format(
                                src_type='crits', id_=crits_id, dest_type='edge'))
                        continue
                    stix_ = stix_pkg(config, src, endpoint, observable)
                    if not stix_:
                        config['logger'].info(
                            log_.log_messages['obj_inbox_error'].format(
                                src_type='crits', id_=crits_id, dest_type='edge'))
                        continue
                    success = edge_.taxii_inbox(config, dest, stix_)
                    if not success:
                        config['logger'].info(
                            log_.log_messages['obj_inbox_error'].format(
                                src_type='crits', id_=crits_id, dest_type='edge'))
                        continue
                    else:
                        config['crits_tally'][endpoint]['processed'] += 1
                        config['crits_tally']['all']['processed'] += 1
                        config['db'].set_object_id(src, dest,
                                                   edge_id=observable.id_,
                                                   crits_id=(xmlns_name + ':' + 
                                                             endpoint + '-' + crits_id))
    for endpoint in endpoints:
        if config['crits_tally'][endpoint]['incoming'] > 0:
            config['logger'].info(log_.log_messages['incoming_tally'].format(
                    count=config['crits_tally'][endpoint]['incoming'],
                    type_=endpoint, src='crits', dest='edge'))
        if (config['crits_tally'][endpoint]['incoming'] -
                   config['crits_tally'][endpoint]['processed']) > 0:
            config['logger'].info(log_.log_messages['failed_tally'].format(
                    count=(config['crits_tally'][endpoint]['incoming'] -
                           config['crits_tally'][endpoint]['processed']),
                    type_=endpoint, src='crits', dest='edge'))
        if config['crits_tally'][endpoint]['processed'] > 0:
            config['logger'].info(log_.log_messages['processed_tally'].format(
                    count=config['crits_tally'][endpoint]['processed'], 
                    type_=endpoint, src='crits', dest='edge'))
    if config['crits_tally']['all']['incoming'] > 0:
        config['logger'].info(log_.log_messages['incoming_tally'].format(
                count=config['crits_tally']['all']['incoming'], type_='total',
                src='crits', dest='edge'))
    if (config['crits_tally']['all']['incoming'] -
               config['crits_tally']['all']['processed']) > 0:
        config['logger'].info(log_.log_messages['failed_tally'].format(
                count=(config['crits_tally']['all']['incoming'] -
                       config['crits_tally']['all']['processed']),
                type_='total', src='crits', dest='edge'))
    if config['crits_tally']['all']['processed'] > 0:
        config['logger'].info(log_.log_messages['processed_tally'].format(
                count=config['crits_tally']['all']['processed'], type_='total',
                src='crits', dest='edge'))
    # save state to disk for next run...
    if config['daemon']['debug']:
        poll_interval = config['crits']['sites'][src]['api']['poll_interval']
        config['logger'].debug(
            log_.log_messages['saving_state'].format(
                next_run=str(now + datetime.timedelta(seconds=poll_interval))))
    if not daemon:
        config['db'].set_last_sync(src=src, dest=dest,
                                   direction='c2e', timestamp=now)
        return(None)
    else:
        return(util_.nowutc())
