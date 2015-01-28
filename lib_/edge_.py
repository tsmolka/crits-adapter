#!/usr/bin/env python2.7

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
import StringIO
import crits_
import datetime
import libtaxii as t
import libtaxii.clients as tc
import libtaxii.messages_10 as tm10
import libtaxii.messages_11 as tm11
import log_
import lxml.etree
import pytz
import util_
import yaml


def mark_crits_releasability(config, source):
    '''add releasability markings to crits json'''
    json = dict()
    json['releasability'] = \
        [{'name':
          config['crits']['sites'][source]['api']['source'],
          'analyst':
          config['crits']['sites'][source]['api']['user'],
          'instances': []}]
    json['c-releasability.name'] = \
        config['crits']['sites'][source]['api']['source']
    json['releasability.name'] = \
        config['crits']['sites'][source]['api']['source']
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
    endpoint = 'ips'
    condition = util_.rgetattr(observable.object_.properties, ['condition'])
    if condition in ['Equals', None]:
        # currently not handling other observable conditions as
        # it's not clear that crits even supports these...
        ip_category = util_.rgetattr(observable.object_.properties,
                                     ['category'])
        ip_value = util_.rgetattr(observable.object_.properties,
                                  ['address_value', 'value'])
        if ip_value and ip_category:
            json = {'ip': ip_value, 'ip_type': crits_types[ip_category]}
            json['stix_id'] = observable.id_
            return(json, endpoint)


def cybox_domain_to_json(config, observable):
    '''translate a cybox domain object to crits json'''
    crits_types = {'FQDN': 'A'}
    # crits doesn't appear to support tlds...
    endpoint = 'domains'
    domain_category = util_.rgetattr(observable.object_.properties, ['type_'])
    domain_value = util_.rgetattr(observable.object_.properties,
                                  ['value', 'value'])
    if domain_category and domain_value:
        json = {'domain': domain_value, 'type': crits_types[domain_category]}
        json['stix_id'] = observable.id_
        return(json, endpoint)


def cybox_uri_to_json(config, observable):
    '''translate a cybox uri object to crits json'''
    crits_types = {'Domain Name': 'A'}
    # urls currently not supported...
    endpoint = 'domains'
    domain_category = util_.rgetattr(observable.object_.properties,
                                     ['type_'])
    domain_value = util_.rgetattr(observable.object_.properties,
                                  ['value', 'value'])
    if domain_category and domain_value:
        if domain_category not in crits_types.keys():
            config['logger'].error('unsupported stix object type %s!'
                                   % type(props))
            endpoint = None
            return(None, endpoint)
        json = {'domain': domain_value, 'type': crits_types[domain_category]}
        json['stix_id'] = observable.id_
        return(json, endpoint)


def cybox_file_to_json(config, observable):
    '''translate a cybox file object to crits json'''
    crits_types = {'MD5': 'md5',
                   'SHA1': 'sha1',
                   'SHA224': 'sha224',
                   'SHA256': 'sha256',
                   'SHA384': 'sha384',
                   'SHA512': 'sha512',
                   'SSDEEP': 'ssdeep'}
    endpoint = 'samples'
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
    return(json, endpoint)


def cybox_email_to_json(config, observable):
    '''translate a cybox email object to crits json'''
    crits_types = {'subject': 'subject', 'to': 'to', 'cc': 'cc',
                   'from_': 'from_address', 'sender': 'sender', 'date': 'date',
                   'message_id': 'message_id', 'reply_to': 'reply_to',
                   'boundary': 'boundary', 'x_mailer': 'x_mailer',
                   'x_originating_ip': 'x_originating_ip'}
    json = {'upload_type': 'fields'}
    endpoint = 'emails'
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
    return(json, endpoint)


def cybox_observable_to_json(config, observable):
    '''translate a straight-up cybox observable to crits json'''
    props = util_.rgetattr(observable.object_, ['properties'])
    if props and isinstance(props, Address):
        (json, endpoint) = cybox_address_to_json(config, observable)
    elif props and isinstance(props, DomainName):
        (json, endpoint) = cybox_domain_to_json(config, observable)
    elif props and isinstance(props, URI):
        (json, endpoint) = cybox_uri_to_json(config, observable)
    elif props and isinstance(props, File):
        (json, endpoint) = cybox_file_to_json(config, observable)
    elif props and isinstance(props, EmailMessage):
        (json, endpoint) = cybox_email_to_json(config, observable)
    if json and endpoint:
        return(json, endpoint)
    else:
        config['logger'].error('unsupported stix object type %s!' %
                               type(props))
        return(None, None)


def stix_ind2json(config, source, destination, indicator,
                  observable_compositions, problem_children):
    '''translate a stix indicator to crits json'''
    endpoint_trans = {'emails': 'Email', 'ips': 'IP',
                      'samples': 'Sample', 'domains': 'Domain'}
    indicator_json = dict()
    relationship_json = list()
    unresolvables = list()
    indicator_json['stix_id'] = indicator.id_
    indicator_json['type'] = 'Reference'
    indicator_json['value'] = util_.rgetattr(indicator, ['title'],
                                             default_='unknown')
    indicator_json['indicator_confidence'] = \
        util_.rgetattr(indicator, ['confidence', 'value', 'value'],
                       default_='unknown')
    # TODO lookup the corresponding stix prop for indicator_impact
    indicator_json['indicator_impact'] = {'rating': 'unknown'}
    if util_.rgetattr(indicator, ['observables']):
        # it's (presumably) a normal observable composition indicator
        container_observable = indicator.observables[0]
        composite_observable_id = util_.rgetattr(container_observable,
                                                 ['idref'])
        if not composite_observable_id:
            config['logger'].error('unable to dereference observable '
                                   'composition for stix indicator %s!'
                                   % indicator.id_)
        else:
            composite_observable = observable_compositions.get(
                composite_observable_id, None)
            if not composite_observable:
                config['logger'].error('unable to dereference observable '
                                       'composition for stix indicator %s!'
                                       % indicator.id_)
            else:
                observables_list = \
                    util_.rgetattr(composite_observable,
                                   ['observable_composition',
                                    'observables'])
                if not observables_list:
                    config['logger'].error('unable to dereference observable '
                                           'composition for stix indicator %s!'
                                           % indicator.id_)
                else:
                    for i in observables_list:
                        if i.idref in problem_children:
                            config['logger'].error('observable %s '
                                                   '(part of observable '
                                                   'composition for stix '
                                                   'indicator %s) could '
                                                   'not be inboxed to '
                                                   'crits; ignoring...'
                                                   % (i.idref, indicator.id_))
                            observables_list.remove(i)
                            continue
                        blob = dict()
                        blob['left_type'] = 'Indicator'
                        blob['left_id'] = None
                        rhs = config['db'].get_object_id(source, destination,
                                                         edge_id=i.idref)
                        if not rhs:
                            config['logger'].error('unable to dereference '
                                                   'observable composition '
                                                   'for stix indicator %s!'
                                                   % indicator.id_)
                            unresolvables.append(i.idref)
                        else:
                            if not rhs.get('crits_id', None):
                                config['logger'].error('unable to dereference '
                                                       'observable '
                                                       'composition '
                                                       'for stix indicator %s!'
                                                       % indicator.id_)
                            else:
                                blob['right_type'] = \
                                    endpoint_trans[
                                        rhs['crits_id'].split(':')[0]]
                                blob['right_id'] = \
                                    rhs['crits_id'].split(':')[1]
                                blob['rel_type'] = 'Contains'
                                blob['rel_confidence'] = 'unknown'
                                relationship_json.append(blob)
    return(indicator_json, relationship_json, unresolvables)



def process_taxii_content_blocks(config, content_block):
    '''process taxii content blocks'''
    observable_endpoints = ['ips', 'domains', 'samples', 'emails']
    json_ = dict()
    for endpoint in observable_endpoints:
        json_[endpoint] = list()
    json_['indicators'] = dict()
    json_['relationships'] = dict()
    observable_compositions = dict()
    indicators = dict()
    xml = StringIO.StringIO(content_block.content)
    stix_package = STIXPackage.from_xml(xml)
    xml.close()
    if stix_package.observables:
        for observable in stix_package.observables.observables:
            if util_.rgetattr(observable, ['object_']):
                (json, endpoint) = \
                    cybox_observable_to_json(config, observable)
                if json:
                    # mark crits releasability...
                    # json.update(mark_crits_releasability(
                    #     config, source))
                    json_[endpoint].append(json)
                else:
                    config['logger'].error('observable %s stix '
                                           'could not be converted '
                                           'to crits json!'
                                           % str(observable.id_))
            elif util_.rgetattr(observable, ['observable_composition',
                                             'observables']):
                observable_compositions[observable.id_] = observable
            else:
                config['logger'].error('observable %s stix could not '
                                       'be converted to crits json!'
                                       % str(observable.id_))
    if stix_package.indicators:
        for i in stix_package.indicators:
            indicators[i.id_] = i
    return(json_, indicators, observable_compositions)


def taxii_poll(config, source, destination, timestamp=None):
    '''pull stix from edge via taxii'''
    client = tc.HttpClient()
    client.setUseHttps(config['edge']['sites'][source]['taxii']['ssl'])
    client.setAuthType(client.AUTH_BASIC)
    client.setAuthCredentials(
        {'username': config['edge']['sites'][source]['taxii']['user'],
         'password': config['edge']['sites'][source]['taxii']['pass']})
    if not timestamp:
        earliest = util_.epoch_start()
    else:
        earliest = timestamp
    latest = util_.nowutc()
    poll_request = tm10.PollRequest(
        message_id=tm10.generate_message_id(),
        feed_name=config['edge']['sites'][source]['taxii']['collection'],
        exclusive_begin_timestamp_label=earliest,
        inclusive_end_timestamp_label=latest,
        content_bindings=[t.CB_STIX_XML_11])
    http_response = client.callTaxiiService2(
        config['edge']['sites'][source]['host'],
        config['edge']['sites'][source]['taxii']['path'],
        t.VID_TAXII_XML_10, poll_request.to_xml(),
        port=config['edge']['sites'][source]['taxii']['port'])
    taxii_message = t.get_message_from_http_response(http_response,
                                                     poll_request.message_id)
    if isinstance(taxii_message, tm10.StatusMessage):
        config['logger'].error('unhandled taxii polling error! (%s)'
                               % taxii_message.message)
    elif isinstance(taxii_message, tm10.PollResponse):
        observable_endpoints = ['ips', 'domains', 'samples', 'emails']
        json_ = dict()
        for endpoint in observable_endpoints:
            json_[endpoint] = list()
        json_['indicators'] = dict()
        json_['relationships'] = dict()
        observable_compositions = dict()
        indicators = dict()
        for content_block in taxii_message.content_blocks:
            (__json, __indicators, __observable_compositions) = \
                process_taxii_content_blocks(config, content_block)
            json_.update(__json)
            indicators.update(__indicators)
            observable_compositions.update(__observable_compositions)
        return(json_, latest, indicators, observable_compositions)


def taxii_inbox(config, target, stix_package=None):
    '''inbox a stix package via taxii'''
    if stix_package:
        stixroot = lxml.etree.fromstring(stix_package.to_xml())
        client = tc.HttpClient()
        client.setUseHttps(config['edge']['sites'][target]['taxii']['ssl'])
        client.setAuthType(client.AUTH_BASIC)
        client.setAuthCredentials(
            {'username':
             config['edge']['sites'][target]['taxii']['user'],
             'password':
             config['edge']['sites'][target]['taxii']['pass']})
        message = tm11.InboxMessage(message_id=tm11.generate_message_id())
        content_block = tm11.ContentBlock(content_binding=t.CB_STIX_XML_11,
                                          content=stixroot)
        if config['edge']['sites'][target]['taxii']['collection'] != \
           'system.Default':
            message.destination_collection_names = \
                [config['edge']['sites'][target]['taxii']['collection']]
        message.content_blocks.append(content_block)
        if config['daemon']['debug']:
            config['logger'].debug('initiating taxii connection to %s'
                                   % target)
        taxii_response = client.callTaxiiService2(
            config['edge']['sites'][target]['host'],
            config['edge']['sites'][target]['taxii']['path'],
            t.VID_TAXII_XML_11, message.to_xml(),
            port=config['edge']['sites'][target]['taxii']['port'])
        if taxii_response.code != 200 or taxii_response.msg != 'OK':
            success = False
            config['logger'].error('taxii inboxing to %s failed! [%s]'
                                   % (target, taxii_response.msg))
        else:
            success = True
            if config['daemon']['debug']:
                config['logger'].debug('taxii inboxing to %s was successful'
                                       % target)
        return(success)


def edge2crits(config, source, destination, daemon=False, now=None,
               last_run=None):
    '''sync an edge instance with crits'''
    # import pudb; pu.db
    observable_endpoints = ['ips', 'domains', 'samples', 'emails']
    endpoint_trans = {'emails': 'Email', 'ips': 'IP',
                      'samples': 'Sample', 'domains': 'Domain'}
    # check if (and when) we synced source and destination...
    if not now:
        now = util_.nowutc()
    if not last_run:
        # didn't get last_run as an arg so check the db...
        last_run = config['db'].get_last_sync(
            source=source, destination=destination,
            direction='edge2crits').replace(tzinfo=pytz.utc)
    config['logger'].info('syncing new edge data since %s between %s and %s'
                          % (str(last_run), source, destination))
    # poll for new edge data...
    (json_, latest, indicators, observable_compositions) = \
        taxii_poll(config, source, destination, last_run)
    # setup counters for logging...
    total_input = 0
    total_output = 0
    subtotal_input = {}
    subtotal_output = {}
    subtotal_input['indicators'] = 0
    subtotal_output['indicators'] = 0
    unresolvables_dict = dict()
    resolved_crits_relationships = list()
    # get counts by endpoint for observables to be processed...
    for endpoint in observable_endpoints:
        subtotal_input[endpoint] = 0
        subtotal_output[endpoint] = 0
        for blob in json_[endpoint]:
            # check whether the observable has already been ingested...
            sync_state = \
                config['db'].get_object_id(source, destination,
                                           edge_id=blob['stix_id'])
            if sync_state:
                if sync_state.get('crits_id', None):
                    if config['daemon']['debug']:
                        config['logger'].debug('edge object id %s '
                                               'already in system'
                                               % blob['stix_id'])
                        # ...and don't process it if we already have it
                        # in the system
                        json_[endpoint].remove(blob)
            else:
                total_input += 1
                subtotal_input[endpoint] += 1
    # get counts by for indicators to be processed...
    for i in indicators.keys():
        # check whether the indicator has already been ingested...
        sync_state = config['db'].get_object_id(source, destination, edge_id=i)
        if sync_state:
            if sync_state.get('crits_id', None):
                if config['daemon']['debug']:
                    config['logger'].debug('edge object id %s '
                                           'already in system' % i)
                    # ...and don't process it if we already have it
                    # in the system
                    del indicators[i]
        else:
            total_input += 1
            subtotal_input['indicators'] += 1
    if total_input > 0:
        config['logger'].info('%i (total) objects to be synced between '
                              '%s (edge) and %s (crits)'
                              % (total_input, source, destination))
    problem_children = list()
    # sync observables...
    for endpoint in observable_endpoints:
        if subtotal_input[endpoint] > 0:
            config['logger'].info('%i %s objects to be synced between '
                                  '%s (edge) and %s (crits)'
                                  % (subtotal_input[endpoint],
                                     endpoint, source, destination))
        for blob in json_[endpoint]:
            stix_id = blob['stix_id']
            del blob['stix_id']
            # inbox the observable to crits...
            (id_, success) = crits_.crits_inbox(config, destination,
                                                endpoint, blob)
            if not success:
                config['logger'].error('%s object with id %s could not '
                                       'be synced from %s (edge) to '
                                       '%s (crits)!'
                                       % (endpoint, str(stix_id),
                                          source, destination))
                problem_children.append(stix_id)
            else:
                # successfully inboxed observable...
                if config['daemon']['debug']:
                    config['logger'].debug('%s object with id %s was synced '
                                           'from %s (edge) to %s (crits)'
                                           % (endpoint, str(stix_id),
                                              source, destination))
                # check whether this observable resolves a crits
                # indicator relationship...
                doc = \
                    config['db'].get_pending_crits_link(source,
                                                        destination,
                                                        edge_id=stix_id)
                if doc:
                    if doc.get('crits_indicator_id', None):
                        resolved_relationship_blob = dict()
                        resolved_relationship_blob['stix_id'] = stix_id
                        resolved_relationship_blob['left_type'] = 'Indicator'
                        resolved_relationship_blob['left_id'] = \
                            doc['crits_indicator_id']
                        resolved_relationship_blob['right_type'] = \
                            endpoint_trans[endpoint]
                        resolved_relationship_blob['right_id'] = id_
                        resolved_relationship_blob['rel_type'] = 'Contains'
                        resolved_relationship_blob['rel_confidence'] = \
                            'unknown'
                        resolved_crits_relationships.append(
                            resolved_relationship_blob)
                # as we've now successfully processed the observable,
                # track the related crits/json ids (by source/dest)
                config['db'].set_object_id(source, destination,
                                           edge_id=stix_id,
                                           crits_id=endpoint +
                                           ':' + str(id_),
                                           timestamp=util_.nowutc())
                subtotal_output[endpoint] += 1
                total_output += 1
        if subtotal_output[endpoint] > 0:
            config['logger'].info('%i %s objects successfully synced between '
                                  '%s (edge) and %s (crits)'
                                  % (subtotal_output[endpoint], endpoint,
                                     source, destination))
        if subtotal_output[endpoint] < subtotal_input[endpoint]:
            config['logger'].info('%i %s objects could not be synced between '
                                  '%s (edge) and %s (crits)'
                                  % (subtotal_input[endpoint] -
                                     subtotal_output[endpoint],
                                     endpoint, source, destination))
    # generate json for indicators (must be after observables because
    # we need to know what id crits assigned for related observables)
    for i in indicators.keys():
        (indicator_json, relationships_json, unresolvables) = \
            stix_ind2json(config, source, destination,
                          indicators[i], observable_compositions,
                          problem_children)
        if unresolvables:
            unresolvables_dict[indicator_json['stix_id']] = unresolvables
        if indicator_json:
            # mark crits releasability...
            # json.update(mark_crits_releasability( config, source))
            json_['indicators'][i] = indicator_json
        else:
            config['logger'].error('indicator %s stix could not be converted '
                                   'to crits json!' % str(i))
        if relationships_json:
            # mark crits releasability...
            # json.update(mark_crits_releasability( config, source))
            json_['relationships'][i] = relationships_json
        else:
            config['logger'].error('indicator %s stix could not be converted '
                                   'to crits json!' % str(i))
    # sync indicators...
    for i in json_['indicators'].keys():
        stix_id = json_['indicators'][i]['stix_id']
        del json_['indicators'][i]['stix_id']
        # inbox the indicator to crits...
        (id_, success) = crits_.crits_inbox(config, destination,
                                            'indicators',
                                            json_['indicators'][i])
        if not success:
            config['logger'].error('%s object with id %s could not be synced '
                                   'from %s (edge) to %s (crits)!'
                                   % ('indicators', str(stix_id),
                                      source, destination))
        else:
            # successfully inboxed indicator...
            if config['daemon']['debug']:
                config['logger'].debug('%s object with id %s was synced from '
                                       '%s (edge) to %s (crits)'
                                       % ('indicators', str(stix_id),
                                          source, destination))
            # track unresolvable cybox observables in db so if we see
            # them later we can build the corresponding crits
            # relationship
            if stix_id in unresolvables_dict.keys():
                for unresolvable in unresolvables_dict[stix_id]:
                    if config['daemon']['debug']:
                        config['logger'].debug('cybox observable id %s should '
                                               'be linked to crits indicator '
                                               'id %s but we haven\'t seen it '
                                               'yet so tracking it in mongo'
                                               % (str(stix_id), id_))
                    config['db'].set_pending_crits_link(source, destination,
                                                        crits_id=id_,
                                                        edge_id=unresolvable)
            # if indicator was inboxed successfully, inbox the
            # connected relationships...
            if json_['relationships'].get(i, None):
                for blob in json_['relationships'][i]:
                    blob['left_id'] = id_
                    (relationship_id_, success) = \
                        crits_.crits_inbox(config, destination,
                                           'relationships', blob)
                    if not success:
                        config['logger'].error('unable to create crits '
                                               'indicator relationship %s '
                                               '(id %s) for crits indicator '
                                               'id %s!'
                                               % (blob['right_type'],
                                                  blob['right_id'], id_))
            # as we've now successfully processed the indicator, track
            # the related crits/json ids (by source/dest)
            config['db'].set_object_id(source, destination,
                                       edge_id=stix_id,
                                       crits_id='indicators:%s'
                                       % str(id_), timestamp=util_.nowutc())
            subtotal_output['indicators'] += 1
            total_output += 1
    if subtotal_output['indicators'] > 0:
        config['logger'].info('%i %s objects successfully synced between '
                              '%s (edge) and %s (crits)'
                              % (subtotal_output['indicators'], 'indicators',
                                 source, destination))
    if subtotal_output['indicators'] < subtotal_input['indicators']:
        config['logger'].info('%i %s objects could not be synced between '
                              '%s (edge) and %s (crits)'
                              % (subtotal_input['indicators'] -
                                 subtotal_output['indicators'], 'indicators',
                                 source, destination))
    if total_output > 0:
        config['logger'].info('%i (total) objects successfully synced between '
                              '%s (edge) and %s (crits)'
                              % (total_output, source, destination))
    if total_output < total_input:
        config['logger'].info('%i (total) objects could not be synced between '
                              '%s (edge) and %s (crits)'
                              % (total_input - total_output,
                                 source, destination))
    # inbox any crits indicator relationships which were resolved by
    # cybox observables inboxed during the current run...
    if resolved_crits_relationships:
        for blob in resolved_crits_relationships:
            stix_id = blob['stix_id']
            del blob['stix_id']
            (relationship_id_, success) = \
                crits_.crits_inbox(config, destination, 'relationships', blob)
            if success:
                config['logger'].debug('resolved outstanding crits indicator '
                                       'relationship %s (id %s) for crits '
                                       'indicator id %s, removing from mongo '
                                       'unresolved relationship tracker'
                                       % (blob['right_type'], blob['right_id'],
                                          blob['left_id']))
                # mark the relationship as resolved in the db...
                config['db'].resolve_crits_link(source, destination,
                                                crits_id=blob['left_id'],
                                                edge_id=stix_id)
    # save state to disk for next run...
    if config['daemon']['debug']:
        poll_interval = \
            config['edge']['sites'][source]['taxii']['poll_interval']
        next_run = str(now + datetime.timedelta(seconds=poll_interval))
        config['logger'].debug('saving state until next run [%s]' % next_run)
    if not daemon:
        config['db'].set_last_sync(source=source, destination=destination,
                                   direction='edge2crits', timestamp=now)
        return(None)
    else:
        return(util_.nowutc())
