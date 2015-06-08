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


from copy import deepcopy
from cybox.common import Hash
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.uri_object import URI
from cybox.objects.email_message_object import EmailMessage, EmailHeader
from cybox.objects.file_object import File
from cybox.utils import Namespace
from cybox.utils import set_id_namespace as set_cybox_id_namespace
from libtaxii.constants import *
from stix.core import STIXPackage, STIXHeader
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.indicator import Indicator
from stix.utils import set_id_namespace as set_stix_id_namespace
from stix.incident import Incident
from stix.common.related import RelatedIndicator, RelatedObservable, RelatedIncident
import StringIO
import crits_
import datetime
import libtaxii as t
import libtaxii.clients as tc
import libtaxii.messages_10 as tm10
import libtaxii.messages_11 as tm11
import log_
import lxml.etree
import util_
import yaml


def mark_crits_releasability(config, dest):
    '''add releasability markings to crits json'''
    json = dict()
    if config['crits']['sites'][dest]['api']['use_releasability']:
        json['releasability'] = \
            [{'name':
              config['crits']['sites'][dest]['api']['releasability'],
              'analyst':
              config['crits']['sites'][dest]['api']['user'],
              'instances': []}]
        json['c-releasability.name'] = \
            config['crits']['sites'][dest]['api']['releasability']
        json['releasability.name'] = \
            config['crits']['sites'][dest]['api']['releasability']
    return(json)


def cybox_address_to_json(config, observable):
    '''translate a cybox address object to crits json'''
    crits_types = {'cidr': 'Address - cidr',
                   'ipv4-addr': 'Address - ipv4-addr',
                   'ipv4-net': 'Address - ipv4-net',
                   'ipv4-netmask': 'Address - ipv4-net-mask',
                   'ipv6-addr': 'Address - ipv6-addr',
                   'ipv6-net': 'Address - ipv6-net',
                   'ipv6-netmask': 'Address - ipv6-net-mask'}
    condition = util_.rgetattr(observable.object_.properties, ['condition'])
    if condition in ['Equals', None]:
        # currently not handling other observable conditions as
        # it's not clear that crits even supports these...
        ip_category = util_.rgetattr(observable.object_.properties,
                                     ['category'])
        ip_value = util_.rgetattr(observable.object_.properties,
                                  ['address_value', 'value'])
        if ip_value and ip_category:
            if ip_category not in crits_types.keys():
                config['logger'].error(
                    log_.log_messages['unsupported_object_error'].format(
                        type_='edge', obj_type=(str(type(observable.object_.properties)) 
                                                + ', %s' % ip_category), id_=observable.id_))
                return(None)
            json = {'ip': ip_value, 'ip_type': crits_types[ip_category]}
            json['stix_id'] = observable.id_
            return(json)


def cybox_domain_to_json(config, observable):
    '''translate a cybox domain object to crits json'''
    crits_types = {'FQDN': 'A'}
    # crits doesn't appear to support tlds...
    domain_category = util_.rgetattr(observable.object_.properties, ['type_'])
    domain_value = util_.rgetattr(observable.object_.properties,
                                  ['value', 'value'])
    if domain_category and domain_value:
        json = {'domain': domain_value, 'type': crits_types[domain_category]}
        json['stix_id'] = observable.id_
        return(json)


def cybox_uri_to_json(config, observable):
    '''translate a cybox uri object to crits json'''
    crits_types = {'Domain Name': 'A'}
    # urls currently not supported...
    domain_category = util_.rgetattr(observable.object_.properties,
                                     ['type_'])
    domain_value = util_.rgetattr(observable.object_.properties,
                                  ['value', 'value'])
    if domain_category and domain_value:
        if domain_category not in crits_types.keys():
            config['logger'].error(
                log_.log_messages['unsupported_object_error'].format(
                    type_='edge', obj_type=(str(type(observable.object_.properties)) 
                                            + ', %s' % domain_category), id_=observable.id_))
            return(None)
        json = {'domain': domain_value, 'type': crits_types[domain_category]}
        json['stix_id'] = observable.id_
        return(json)


def cybox_file_to_json(config, observable):
    '''translate a cybox file object to crits json'''
    crits_types = {'MD5': 'md5',
                   'SHA1': 'sha1',
                   'SHA224': 'sha224',
                   'SHA256': 'sha256',
                   'SHA384': 'sha384',
                   'SHA512': 'sha512',
                   'SSDEEP': 'ssdeep'}
    json = {'upload_type': 'metadata'}
    hashes = util_.rgetattr(observable.object_.properties, ['hashes'])
    if hashes:
        for hash in hashes:
            hash_type = util_.rgetattr(hash, ['type_', 'value'])
            hash_value = util_.rgetattr(hash, ['simple_hash_value', 'value'])
            if hash_type and hash_value:
                json[crits_types[hash_type]] = hash_value
    file_name = util_.rgetattr(observable.object_.properties,
                               ['file_name', 'value'])
    if file_name:
        json['filename'] = file_name
    file_format = util_.rgetattr(observable.object_.properties,
                                 ['file_format', 'value'])
    if file_format:
        json['filetype'] = file_format
    file_size = util_.rgetattr(observable.object_.properties,
                               ['size_in_bytes', 'value'])
    if file_size:
        json['size'] = file_size
    json['stix_id'] = observable.id_
    return(json)


def cybox_email_to_json(config, observable):
    '''translate a cybox email object to crits json'''
    crits_types = {'subject': 'subject', 'to': 'to', 'cc': 'cc',
                   'from_': 'from_address', 'sender': 'sender', 'date': 'date',
                   'message_id': 'message_id', 'reply_to': 'reply_to',
                   'boundary': 'boundary', 'x_mailer': 'x_mailer',
                   'x_originating_ip': 'x_originating_ip'}
    json = {'upload_type': 'fields'}
    subject = util_.rgetattr(observable.object_.properties,
                             ['header', 'subject', 'value'])
    if subject:
        json['subject'] = subject
    to = util_.rgetattr(observable.object_.properties, ['header', 'to'])
    if to:
        json['to'] = []
        for i in to:
            addr = util_.rgetattr(i, ['address_value', 'values'])
            if addr:
                json['to'].append(addr)
    cc = util_.rgetattr(observable.object_.properties, ['header', 'cc'])
    if cc:
        json['cc'] = []
        for i in cc:
            addr = util_.rgetattr(i, ['address_value', 'values'])
            if addr:
                json['cc'].append(addr)
    from_ = util_.rgetattr(observable.object_.properties,
                           ['header', 'from_', 'address_value', 'value'])
    if from_:
        json['from_address'] = [from_]
    sender = util_.rgetattr(observable.object_.properties,
                            ['header', 'sender', 'address_value', 'value'])
    if sender:
        json['sender'] = sender
    date = util_.rgetattr(observable.object_.properties,
                          ['header', 'date', 'value'])
    if date:
        json['date'] = date
    message_id = util_.rgetattr(observable.object_.properties,
                                ['header', 'message_id', 'value'])
    if message_id:
        json['message_id'] = message_id
    reply_to = util_.rgetattr(observable.object_.properties,
                              ['header', 'reply_to', 'address_value', 'value'])
    if reply_to:
        json['reply_to'] = reply_to
    boundary = util_.rgetattr(observable.object_.properties,
                              ['header', 'boundary', 'value'])
    if boundary:
        json['boundary'] = boundary
    x_mailer = util_.rgetattr(observable.object_.properties,
                              ['header', 'x_mailer', 'value'])
    if x_mailer:
        json['x_mailer'] = x_mailer
    x_originating_ip = util_.rgetattr(observable.object_.properties,
                                      ['header', 'x_originating_ip', 'value'])
    if x_originating_ip:
        json['x_originating_ip'] = x_originating_ip
    json['stix_id'] = observable.id_
    return(json)


def cybox_observable_to_json(config, observable):
    '''translate a cybox observable to crits json'''
    props = util_.rgetattr(observable.object_, ['properties'])
    if props and isinstance(props, Address):
        endpoint = 'ips'
        json = cybox_address_to_json(config, observable)
    elif props and isinstance(props, DomainName):
        endpoint = 'domains'
        json = cybox_domain_to_json(config, observable)
    elif props and isinstance(props, URI):
        endpoint = 'domains'
        json = cybox_uri_to_json(config, observable)
    elif props and isinstance(props, File):
        endpoint = 'samples'
        json = cybox_file_to_json(config, observable)
    elif props and isinstance(props, EmailMessage):
        endpoint = 'emails'
        json = cybox_email_to_json(config, observable)
    if json and endpoint:
        # TODO: this would all be a helluva lot easier if the crits
        #       api supported manually setting an _id
        #
        # json['_id'] = observable.id_.split('-')[1]
        return(json, endpoint)
    else:
        config['logger'].error(
            log_.log_messages['unsupported_object_error'].format(
                type_='edge', obj_type=type(props), id_=observable.id_))
        return(None, None)


def process_observables(config, src, dest, observables):
    '''handle incoming cybox observables and observable compositions'''
    # TODO some of the hailataxii date uses the cybox ###comma###
    #      construct, which is currently unsupported
    for o_id, o in observables.iteritems():
        json = dict()
        if util_.rgetattr(o, ['observable_composition']) \
           and not util_.rgetattr(o, ['object_']):
            # it's an observable composition
            # store it in the db...maybe the indicator will only come
            # across in a subsequent run so we can't rely on passing
            # this around in memory
            config['db'].store_obs_comp(src, dest,
                                        obs_id=o_id,
                                        obs_comp=o.observable_composition)
            continue
        elif util_.rgetattr(o, ['object_']):
            # it's a normal observable
            (json, endpoint) = cybox_observable_to_json(config, o)
            if not json:
                config['logger'].error(
                    log_.log_messages[
                        'obj_convert_error'].format(src_type='cybox',
                                                    src_obj='observable',
                                                    id_=o_id,
                                                    dest_type='crits',
                                                    dest_obj='json'))
                continue

            # mark crits releasability
            # TODO: Maybe remove this? Not sure if it works with
            # the Crits PATCH API method for setting releasability. 
            json.update(mark_crits_releasability(config, dest))

            # inbox the observable to crits
            config['edge_tally'][endpoint]['incoming'] += 1
            config['edge_tally']['all']['incoming'] += 1
            (id_, success) = \
                crits_.crits_inbox(config, dest, endpoint, json,
                                   src=src, edge_id=o_id)
            if not success:
                config['logger'].error(
                    log_.log_messages['obj_inbox_error'].format(
                        src_type='edge', id_=o, dest_type='crits ' + endpoint + ' api endpoint'))
                continue

            # Successfully inboxed observable
            patch_endpoint = '{}/{}'.format(endpoint, id_)

            # Send Patch request to set crits releasability
            releasability_json = {
                'action': 'add_releasability',
                'name': config['crits']['sites'][dest]['api']['releasability'],
            }
            crits_.crits_patch(config, dest, 
                patch_endpoint, releasability_json, src=src, edge_id=o_id)

            config['edge_tally'][endpoint]['processed'] += 1
            config['edge_tally']['all']['processed'] += 1
            if config['daemon']['debug']:
                config['logger'].debug(
                    log_.log_messages['obj_inbox_success'].format(
                        src_type='edge', id_=o_id,
                        dest_type='crits ' + endpoint + ' api endpoint'))


def process_incidents(config, src, dest, incidents):
    '''handle incoming stix incidents'''
    xmlns_name = config['edge']['sites'][src]['stix']['xmlns_name']
    status_trans = {'New': 'New', 'Open': 'In Progress',
                    'Closed': 'Analyzed', 'Rejected': 'Deprecated'}
    for i in incidents.keys():
        json = dict()
        json['event_type'] = 'Threat Report'
        json['title'] = incidents[i].title
        json['description'] = util_.rgetattr(incidents[i], ['description', 'value'])
        json['status'] = status_trans[incidents[i].status.value]
        # inbox the incident (we need to crits id!)
        config['edge_tally']['events']['incoming'] += 1
        config['edge_tally']['all']['incoming'] += 1
        (crits_event_id, success) = crits_.crits_inbox(config, dest,
                                                       'events',
                                                       json, src=src)
        if not success:
            config['logger'].error(
                log_.log_messages['obj_inbox_error'].format(
                    src_type='edge', id_=i, 
                    dest_type='crits events api endpoint'))
            continue
        else:
            # successfully inboxed event...
            config['edge_tally']['events']['processed'] += 1
            config['edge_tally']['all']['processed'] += 1
            if config['daemon']['debug']:
                config['logger'].debug(
                    log_.log_messages['obj_inbox_success'].format(
                        src_type='edge', id_=i,
                        dest_type='crits events api endpoint'))
        # as we've now successfully processed the event, track
        # the related crits/json ids (by src/dest)
        if util_.rgetattr(incidents[i], ['related_observables']) and len(incidents[i].related_observables):
            for j in incidents[i].related_observables:
                if util_.rgetattr(j, ['item', 'idref']):
                    # store the pending relationship in the db for
                    # later processing 
                    config['db'].set_pending_crits_link(src, dest,
                                                        lhs_id=(xmlns_name + ':' + 
                                                                  'events' + '-' +
                                                                  crits_event_id),
                                                        rhs_id=j.item.idref)
        if util_.rgetattr(incidents[i], ['related_indicators']) and len(incidents[i].related_indicators):
            for j in incidents[i].related_indicators:
                if util_.rgetattr(j, ['item', 'idref']):
                    # store the pending relationship in the db for
                    # later processing 
                    config['db'].set_pending_crits_link(src, dest,
                                                        lhs_id=(xmlns_name + ':' + 
                                                                  'events' + '-' +
                                                                  crits_event_id),
                                                        rhs_id=j.item.idref)
        if util_.rgetattr(incidents[i], ['related_incidents']) and len(incidents[i].related_incidents):
            for j in incidents[i].related_incidents:
                if util_.rgetattr(j, ['item', 'idref']):
                    # store the pending relationship in the db for
                    # later processing 
                    config['db'].set_pending_crits_link(src, dest,
                                                        lhs_id=(xmlns_name + ':' + 
                                                                  'events' + '-' +
                                                                  crits_event_id),
                                                        rhs_id=j.item.idref)
                                        
        config['db'].set_object_id(src, dest,
                                   edge_id=i,
                                   crits_id=(xmlns_name + ':' + 'events' + '-' +
                                             crits_event_id))


def process_indicators(config, src, dest, indicators):
    '''handle incoming stix indicators'''
    xmlns_name = config['edge']['sites'][src]['stix']['xmlns_name']
    for i in indicators.keys():
        json = dict()
        json['type'] = 'Related_To'
        json['value'] = util_.rgetattr(indicators[i], ['title'],
                                       default_='unknown')
        json['indicator_confidence'] = \
            util_.rgetattr(indicators[i], ['confidence', 'value', 'value'],
                           default_='unknown')
        # TODO lookup the corresponding stix prop for indicator_impact
        json['indicator_impact'] = {'rating': 'unknown'}
        # inbox the indicator (we need to crits id!)
        config['edge_tally']['indicators']['incoming'] += 1
        config['edge_tally']['all']['incoming'] += 1
        (crits_indicator_id, success) = crits_.crits_inbox(config, dest,
                                                           'indicators',
                                                           json, src=src)
        if not success:
            config['logger'].error(
                log_.log_messages['obj_inbox_error'].format(
                    src_type='edge', id_=i, 
                    dest_type='crits indicators api endpoint'))
            continue
        else:
            # successfully inboxed indicator...
            config['edge_tally']['indicators']['processed'] += 1
            config['edge_tally']['all']['processed'] += 1
            if config['daemon']['debug']:
                config['logger'].debug(
                    log_.log_messages['obj_inbox_success'].format(
                        src_type='edge', id_=i,
                        dest_type='crits indicators api endpoint'))
        if util_.rgetattr(indicators[i], ['observables']):
            for o in indicators[i].observables:
                if util_.rgetattr(o, ['idref']) and \
                   not util_.rgetattr(o, ['object_']):
                    # TODO need to delete observable compositions from
                    #      mongo once we've processed them
                    obs_comp = \
                        config['db'].get_obs_comp(src, dest, obs_id=o.idref)
                    if not obs_comp:
                        # [ o == embedded observable]
                        config['db'].set_pending_crits_link(src, dest,
                                                            lhs_id=(xmlns_name + ':' + 
                                                                      'indicators' + '-' + 
                                                                      crits_indicator_id),
                                                            rhs_id=o.idref)
                    elif obs_comp:
                        # [o == idref observable composition]
                        # try to fetch the observable composition o.idref
                        # points to
                        # assumption: the observable composition was
                        # previously ingested. TODO what about when
                        # the observable composition comes in *after*
                        # the indicator?
                        observables_list = util_.rgetattr(obs_comp,
                                                          ['observables'])
                        if not observables_list:
                            config['logger'].error(
                                log_.log_messages['obs_comp_dereference_error'
                                              ].format(id_=i))
                            continue
                        else:
                            for j in observables_list:
                                # store the pending relationship in
                                # the db for later processing
                                config['db'].set_pending_crits_link(src, dest,
                                                                    lhs_id=(xmlns_name + ':' + 
                                                                              'indicators' + '-' +
                                                                              crits_indicator_id),
                                                                    rhs_id=j.idref)
                    # TODO (need to dig up suitable sample data)
                    # if it's an observable composition with inline
                    # observables, pass them to observable composition with
                    # inline observables, pass them to process_observables(),
                    # (which will store the edge/crits id indicator pairing
                    # for later processing.
                    else:
                        config['logger'].error(
                            log_.log_messages['obs_comp_dereference_error'
                                          ].format(id_=i))
                        continue
        # as we've now successfully processed the indicator, track
        # the related crits/json ids (by src/dest)
        if util_.rgetattr(indicators[i], ['related_indicators']) and len(indicators[i].related_indicators):
            for j in indicators[i].related_indicators:
                if util_.rgetattr(j, ['item', 'idref']):
                    # store the pending relationship in the db for
                    # later processing 

                    # TODO for some reason, the crits relationship api
                    # is rejecting _some_ (but not _all_
                    # indicator-to-indicator relationships. the
                    # indicator ids are valid and the api post looks
                    # correct but...sometimes this fails :-/
                    config['db'].set_pending_crits_link(src, dest,
                                                        lhs_id=(xmlns_name + ':' + 
                                                                  'indicators' + '-' +
                                                                  crits_indicator_id),
                                                        rhs_id=j.item.idref)
                                        
        config['db'].set_object_id(src, dest,
                                   edge_id=i,
                                   crits_id=(xmlns_name + ':' + 'indicators' + '-' +
                                             crits_indicator_id))


def process_relationships(config, src, dest):
    '''forge the crits relationship links between incoming observables
    and indicators'''
    endpoint_trans = {'emails': 'Email', 'ips': 'IP',
                      'samples': 'Sample', 'domains': 'Domain',
                      'indicators': 'Indicator', 'events': 'Event'}
    pending_crits_links = config['db'].get_pending_crits_links(src, dest)
    if not pending_crits_links:
        config['logger'].info(
            log_.log_messages['no_pending_crits_relationships'])
    else:
        for r in pending_crits_links:
            json = dict()
            json['left_type'] = endpoint_trans[r['lhs_id'].split(':')[1].split('-')[0]]
            json['left_id'] = r['lhs_id'].split(':')[1].split('-')[1]
            # try to fetch the crits observable id corresponding to
            # the edge id
            rhs = config['db'].get_object_id(src, dest,
                                             edge_id=r['rhs_id'])
            if not rhs or not rhs.get('crits_id', None):
                config['logger'].error(
                    log_.log_messages['obs_comp_dereference_error'
                                  ].format(id_=r['rhs_id']))
            else:
                json['right_type'] = \
                    endpoint_trans[
                        rhs['crits_id'].split(':')[1].split('-')[0]]
                json['right_id'] = \
                    rhs['crits_id'].split(':')[1].split('-')[1]
                json['rel_type'] = 'Related_To'
                json['rel_confidence'] = 'unknown'
                config['edge_tally']['relationships']['incoming'] += 1
                config['edge_tally']['all']['incoming'] += 1
                (relationship_id_, success) = \
                    crits_.crits_inbox(config, dest,
                                       'relationships', json, src=src)
                if not success:
                    config['logger'].error(
                        log_.log_messages['obj_inbox_error'].format(
                            src_type='edge', id_=r['rhs_id'],
                            dest_type='crits relationships api endpoint'))
                else:
                    # remove the pending crits relationship from the db
                    config['edge_tally']['relationships']['processed'] += 1
                    config['edge_tally']['all']['processed'] += 1
                    config['db'].resolve_crits_link(src, dest,
                                                    lhs_id=r['lhs_id'],
                                                    rhs_id=r['rhs_id'])


def process_taxii_content_blocks(config, content_block):
    '''process taxii content blocks'''
    incidents = dict()
    indicators = dict()
    observables = dict()
    xml = StringIO.StringIO(content_block.content)
    stix_package = STIXPackage.from_xml(xml)
    xml.close()
    if stix_package.incidents:
        for j in stix_package.incidents:
            incidents[j.id_] = j
    if stix_package.indicators:
        for i in stix_package.indicators:
            indicators[i.id_] = i
    if stix_package.observables:
        for o in stix_package.observables.observables:
            observables[o.id_] = o
    return(incidents, indicators, observables)


def taxii_poll(config, src, dest, timestamp=None):
    '''pull stix from edge via taxii'''
    client = tc.HttpClient()
    client.setUseHttps(config['edge']['sites'][src]['taxii']['ssl'])
    client.setAuthType(client.AUTH_BASIC)
    client.setAuthCredentials(
        {'username': config['edge']['sites'][src]['taxii']['user'],
         'password': config['edge']['sites'][src]['taxii']['pass']})
    if not timestamp:
        earliest = util_.epoch_start()
    else:
        earliest = timestamp
    latest = util_.nowutc()
    poll_request = tm10.PollRequest(
       message_id=tm10.generate_message_id(),
        feed_name=config['edge']['sites'][src]['taxii']['collection'],
        exclusive_begin_timestamp_label=earliest,
        inclusive_end_timestamp_label=latest,
        content_bindings=[t.CB_STIX_XML_11])
    http_response = client.callTaxiiService2(
        config['edge']['sites'][src]['host'],
        config['edge']['sites'][src]['taxii']['path'],
        t.VID_TAXII_XML_10, poll_request.to_xml(),
        port=config['edge']['sites'][src]['taxii']['port'])
    taxii_message = t.get_message_from_http_response(http_response,
                                                     poll_request.message_id)
    if isinstance(taxii_message, tm10.StatusMessage):
        config['logger'].error(log_.log_messages['polling_error'].format(
            type_='taxii', error=taxii_message.message))
    elif isinstance(taxii_message, tm10.PollResponse):
        incidents = dict()
        indicators = dict()
        observables = dict()
        for content_block in taxii_message.content_blocks:
            (incidents_, indicators_, observables_) = \
                process_taxii_content_blocks(config, content_block)
            incidents.update(incidents_)
            indicators.update(indicators_)
            observables.update(observables_)
        return(latest, incidents, indicators, observables)


def taxii_inbox(config, dest, stix_package=None, src=None, crits_id=None):
    '''inbox a stix package via taxii'''
    if src and crits_id:
        # check whether this has already been ingested
        sync_state = config['db'].get_object_id(src, dest, crits_id=crits_id)
        if sync_state and sync_state.get('crits_id', None):
            if config['daemon']['debug']:
                config['logger'].debug(
                    log_.log_messages['object_already_ingested'].format(
                        src_type='crits', src_id=crits_id, src=src, 
                        dest_type='edge', dest=dest, dest_id=sync_state['edge_id']))
            return(True)
    if stix_package:
        stixroot = lxml.etree.fromstring(stix_package.to_xml())
        client = tc.HttpClient()
        client.setUseHttps(config['edge']['sites'][dest]['taxii']['ssl'])
        client.setAuthType(client.AUTH_BASIC)
        client.setAuthCredentials(
            {'username':
             config['edge']['sites'][dest]['taxii']['user'],
             'password':
             config['edge']['sites'][dest]['taxii']['pass']})
        message = tm11.InboxMessage(message_id=tm11.generate_message_id())
        content_block = tm11.ContentBlock(content_binding=t.CB_STIX_XML_11,
                                          content=stixroot)
        if config['edge']['sites'][dest]['taxii']['collection'] != \
           'system.Default':
            message.destination_collection_names = \
                [config['edge']['sites'][dest]['taxii']['collection']]
        message.content_blocks.append(content_block)
        if config['daemon']['debug']:
            config['logger'].debug(
                log_.log_messages[
                    'open_session'].format(type_='taxii', host=dest))
        taxii_response = client.callTaxiiService2(
            config['edge']['sites'][dest]['host'],
            config['edge']['sites'][dest]['taxii']['path'],
            t.VID_TAXII_XML_11, message.to_xml(),
            port=config['edge']['sites'][dest]['taxii']['port'])
        if taxii_response.code != 200 or taxii_response.msg != 'OK':
            success = False
            config['logger'].error(
                log_.log_messages[
                    'inbox_error'].format(type_='taxii', host=dest,
                                          msg=taxii_response.msg))
        else:
            success = True
            if config['daemon']['debug']:
                config['logger'].debug(
                    log_.log_messages['inbox_success'].format(type_='taxii',
                                                              host=dest))
        return(success)


def edge2crits(config, src, dest, daemon=False, now=None,
               last_run=None):
    '''sync an edge instance with crits'''
    # check if (and when) we synced src and dest...
    if not now:
        now = util_.nowutc()
    if not last_run:
        # didn't get last_run as an arg so check the db...
        last_run = config['db'].get_last_sync(src=src, dest=dest,
                                              direction='e2c')
    config['logger'].info(log_.log_messages['start_sync'].format(
        type_='edge', last_run=str(last_run), src=src, dest=dest))
    # setup the tally counters
    config['edge_tally'] = dict()
    endpoints = ['ips', 'domains', 'samples', 'emails', 'indicators', 'relationships', 'events']
    config['edge_tally']['all'] = {'incoming': 0, 'processed': 0}
    for endpoint in endpoints:
        config['edge_tally'][endpoint] = {'incoming': 0, 'processed': 0}
    # poll for new edge data...
    (latest, incidents, indicators, observables) = \
        taxii_poll(config, src, dest, last_run)
    process_observables(config, src, dest, observables)
    process_incidents(config, src, dest, incidents)
    process_indicators(config, src, dest, indicators)
    process_relationships(config, src, dest)
    for endpoint in endpoints:
        if config['edge_tally'][endpoint]['incoming'] > 0:
            config['logger'].info(log_.log_messages['incoming_tally'].format(
                    count=config['edge_tally'][endpoint]['incoming'],
                    type_=endpoint, src='edge', dest='crits'))
        if (config['edge_tally'][endpoint]['incoming'] -
                   config['edge_tally'][endpoint]['processed']) > 0:
            config['logger'].info(log_.log_messages['failed_tally'].format(
                    count=(config['edge_tally'][endpoint]['incoming'] -
                           config['edge_tally'][endpoint]['processed']),
                    type_=endpoint, src='edge', dest='crits'))
        if config['edge_tally'][endpoint]['processed'] > 0:
            config['logger'].info(log_.log_messages['processed_tally'].format(
                    count=config['edge_tally'][endpoint]['processed'], 
                    type_=endpoint, src='edge', dest='crits'))
    if config['edge_tally']['all']['incoming'] > 0:
        config['logger'].info(log_.log_messages['incoming_tally'].format(
                count=config['edge_tally']['all']['incoming'], type_='total',
                src='edge', dest='crits'))
    if (config['edge_tally']['all']['incoming'] -
               config['edge_tally']['all']['processed']) > 0:
        config['logger'].info(log_.log_messages['failed_tally'].format(
                count=(config['edge_tally']['all']['incoming'] -
                       config['edge_tally']['all']['processed']),
                type_='total', src='edge', dest='crits'))
    if config['edge_tally']['all']['processed'] > 0:
        config['logger'].info(log_.log_messages['processed_tally'].format(
                count=config['edge_tally']['all']['processed'], type_='total',
                src='edge', dest='crits'))
    # save state to disk for next run...
    if config['daemon']['debug']:
        poll_interval = \
            config['edge']['sites'][src]['taxii']['poll_interval']
        next_run = str(now + datetime.timedelta(seconds=poll_interval))
        config['logger'].debug(log_.log_messages['saving_state'].format(
            next_run=next_run))
    if not daemon:
        config['db'].set_last_sync(src=src, dest=dest,
                                   direction='e2c', timestamp=now)
        return(None)
    else:
        return(util_.nowutc())
