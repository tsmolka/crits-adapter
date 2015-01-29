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
import util_
import yaml


def mark_crits_releasability(config, src):
    '''add releasability markings to crits json'''
    json = dict()
    if config['crits']['sites'][src]['api']['use_releasability']:
        json['releasability'] = \
            [{'name':
              config['crits']['sites'][src]['api']['releasability'],
              'analyst':
              config['crits']['sites'][src]['api']['user'],
              'instances': []}]
        json['c-releasability.name'] = \
            config['crits']['sites'][src]['api']['releasability']
        json['releasability.name'] = \
            config['crits']['sites'][src]['api']['releasability']
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
            config['logger'].error(
                log_messages['unsupported_stix_object_error'].format(
                    type_=type(props), id_=observable.id_))
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
    '''translate a cybox observable to crits json'''
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
        config['logger'].error(
            log_messages['unsupported_stix_object_error'].format(
                type_=type(props), id_=observable.id_))
        return(None, None)


def process_observables(config, src, dest, observables):
    for o in observables.keys():
        json = dict()
        if util_.rgetattr(observables[o], ['object_']):
            (json, endpoint) = cybox_observable_to_json(config, observables[o])
            if json:
                # mark crits releasability
                json.update(mark_crits_releasability(config, src))
            else:
                config['logger'].error(
                    log_messages['observable_convert_error'].format(id_=o))
                # don't process it if we already have it
                del observables[o]
                continue
            # inbox the observable to crits
            (id_, success) = \
                crits_.crits_inbox(config, dest, endpoint, json,
                                   src=src, edge_id=o)
            if not success:
                config['logger'].error(
                    log_messages['crits_inbox_error'].format(
                        id_=o, endpoint=endpoint))
            else:
                # successfully inboxed observable
                if config['daemon']['debug']:
                    config['logger'].debug(
                        log_messages['crits_inbox_success'].format(
                            id_=o, endpoint=endpoint)


def process_indicators(config, src, dest, indicators):
    for i in indicators.keys():
        json = dict()
        json['type'] = 'Reference'
        json['value'] = util_.rgetattr(indicators[i], ['title'],
                                       default_='unknown')
        json['indicator_confidence'] = \
            util_.rgetattr(indicators[i], ['confidence', 'value', 'value'],
                           default_='unknown')
        # TODO lookup the corresponding stix prop for indicator_impact
        json['indicator_impact'] = {'rating': 'unknown'}
        # inbox the indicator (we need to crits id!)
        (indicator_id, success) = crits_.crits_inbox(config, dest,
                                                     'indicators',
                                                     json)
        if not success:
            config['logger'].error(log_messages['crits_inbox_error'].format(
                id_=i, endpoint='indicators'))
        else:
            # successfully inboxed indicator...
            if config['daemon']['debug']:
                config['logger'].debug(log_messages[
                    'crits_inbox_success'].format(id_=i,
                                                  endpoint='indicators'))
        # [pseudocode]
        # for o in indicator observables:
        #     if it's an observable composition with idrefs, call
        #     set_pending_crits_link() to store the edge_id / crits
        #     indicator pairing for later processing.
        # 
        #     elif it's an observable composition with inline
        #     observables, pass them to observable composition with
        #     inline observables, pass them to process_observables(),
        #     (which will store the edge/crits id indicator pairing
        #     for later processing.
        # 
        #     elif it's an indicator with inline observables, pass
        #     them to observable composition with inline observables,
        #     pass them to process_observables(), (which will store
        #     the edge/crits id indicator pairing for later
        #     processing.
        #
        # finally, (write a db func) call
        # db.get_unresolved_crits_links(), loop through them, call
        # get_object_id() to find the crits observable id
        # corresponding to the edge id, generate the relationship
        # json, inbox it to crits, and call resolve_crits_link() if
        # successful
        
        if util_.rgetattr(indicator, ['observables']):
            for o in indicator.observables:
                if util_.rgetattr(o, ['idref']):
                    pass
                elif util_.rgetattr(o, ['object_']):
                    if util_.rgetattr(o.object_, ['properties']):
                        pass

    #     container_observable = indicator.observables[0]
    #     composite_observable_id = \
    #         util_.rgetattr(container_observable, ['idref'])
    #     if not composite_observable_id:
    #         config['logger'].error(
    #             log_messages['obs_comp_dereference_error'].format(
    #                 id_=indicator.id_)
    #     else:
    #         composite_observable = observable_compositions.get(
    #             composite_observable_id, None)
    #         if not composite_observable:
    #             config['logger'].error(
    #                 log_messages['obs_comp_dereference_error'].format(
    #                     id_=indicator.id_)
    #         else:
    #             observables_list = \
    #                 util_.rgetattr(composite_observable,
    #                                ['observable_composition',
    #                                 'observables'])
    #             if not observables_list:
    #                 config['logger'].error(
    #                     log_messages['obs_comp_dereference_error'
    #                              ].format(id_=indicator.id_)
    #             else:
    #                 for i in observables_list:
    #                     blob = dict()
    #                     blob['left_type'] = 'Indicator'
    #                     blob['left_id'] = None
    #                     rhs = config['db'].get_object_id(src, dest,
    #                                                      edge_id=i.idref)
    #                     if not rhs:
    #                         config['logger'].error(
    #                             log_messages['obs_comp_dereference_error'
    #                                      ].format(id_=indicator.id_)
    #                         unresolvables.append(i.idref)
    #                     else:
    #                         if not rhs.get('crits_id', None):
    #                             config['logger'].error(
    #                                 log_messages['obs_comp_dereference_error'
    #                                          ].format(id_=indicator.id_)
    #                         else:
    #                             blob['right_type'] = \
    #                                 endpoint_trans[
    #                                     rhs['crits_id'].split(':')[0]]
    #                             blob['right_id'] = \
    #                                 rhs['crits_id'].split(':')[1]
    #                             blob['rel_type'] = 'Contains'
    #                             blob['rel_confidence'] = 'unknown'
    #                             relationship_json.append(blob)
    # return(indicator_json, relationship_json, unresolvables)


                                   
    #         # track unresolvable cybox observables in db so if we see
    #         # them later we can build the corresponding crits
    #         # relationship
    #         if stix_id in unresolvables_dict.keys():
    #             for unresolvable in unresolvables_dict[stix_id]:
    #                 if config['daemon']['debug']:
    #                     config['logger'].debug('cybox observable id %s should '
    #                                            'be linked to crits indicator '
    #                                            'id %s but we haven\'t seen it '
    #                                            'yet so tracking it in mongo'
    #                                            % (str(stix_id), id_))
    #                 config['db'].set_pending_crits_link(src, dest,
    #                                                     crits_id=id_,
    #                                                     edge_id=unresolvable)
    #         # if indicator was inboxed successfully, inbox the
    #         # connected relationships...
    #         if json_['relationships'].get(i, None):
    #             for blob in json_['relationships'][i]:
    #                 blob['left_id'] = id_
    #                 (relationship_id_, success) = \
    #                     crits_.crits_inbox(config, dest,
    #                                        'relationships', blob)
    #                 if not success:
    #                     config['logger'].error('unable to create crits '
    #                                            'indicator relationship %s '
    #                                            '(id %s) for crits indicator '
    #                                            'id %s!'
    #                                            % (blob['right_type'],
    #                                               blob['right_id'], id_))
    #         # as we've now successfully processed the indicator, track
    #         # the related crits/json ids (by src/dest)
    #         config['db'].set_object_id(src, dest,
    #                                    edge_id=stix_id,
    #                                    crits_id='indicators:%s'
    #                                    % str(id_), timestamp=util_.nowutc())


def process_taxii_content_blocks(config, content_block):
    '''process taxii content blocks'''
    indicators = dict()
    observables = dict()
    xml = StringIO.StringIO(content_block.content)
    stix_package = STIXPackage.from_xml(xml)
    xml.close()
    if stix_package.observables:
        for o in stix_package.observables.observables:
            observables[o.id_] = o
    if stix_package.indicators:
        for i in stix_package.indicators:
            indicators[i.id_] = i
    return(indicators, observables)


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
        config['logger'].error(log_messages['taxii_polling_error'].format(
            error=taxii_message.message))
    elif isinstance(taxii_message, tm10.PollResponse):
        indicators = dict()
        observables = dict()
        for content_block in taxii_message.content_blocks:
            (indicators_, observables_) = \
                process_taxii_content_blocks(config, content_block)
            indicators.update(indicators_)
            observables.update(observables_)
        return(latest, indicators, observables)


def taxii_inbox(config, dest, stix_package=None):
    '''inbox a stix package via taxii'''
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
            config['logger'].debug(log_messages['taxii_open_session'].format(
                host=dest))
        taxii_response = client.callTaxiiService2(
            config['edge']['sites'][dest]['host'],
            config['edge']['sites'][dest]['taxii']['path'],
            t.VID_TAXII_XML_11, message.to_xml(),
            port=config['edge']['sites'][dest]['taxii']['port'])
        if taxii_response.code != 200 or taxii_response.msg != 'OK':
            success = False
            config['logger'].error(log_messages['taxii_inbox_error'].format(
                host=dest, msg=taxii_response.msg))
        else:
            success = True
            if config['daemon']['debug']:
                config['logger'].debug(
                    log_messages['taxii_inbox_success'].format(host=dest))
        return(success)


def edge2crits(config, src, dest, daemon=False, now=None,
               last_run=None):
    '''sync an edge instance with crits'''
    observable_endpoints = ['ips', 'domains', 'samples', 'emails']
    endpoint_trans = {'emails': 'Email', 'ips': 'IP',
                      'samples': 'Sample', 'domains': 'Domain'}
    # check if (and when) we synced src and dest...
    if not now:
        now = util_.nowutc()
    if not last_run:
        # didn't get last_run as an arg so check the db...
        last_run = config['db'].get_last_sync(src=src, dest=dest,
                                              direction='edge2crits')
    config['logger'].info(log_messages['start_sync'].format(
        type_='edge', last_run=str(last_run), src=src, dest=dest))
    # poll for new edge data...
    (latest, indicators, observables) = \
        taxii_poll(config, src, dest, last_run)
    process_observables(config, src, dest, observables)
    process_indicators(config, src, dest, indicators)
    # save state to disk for next run...
    if config['daemon']['debug']:
        poll_interval = \
            config['edge']['sites'][src]['taxii']['poll_interval']
        next_run = str(now + datetime.timedelta(seconds=poll_interval))
        config['logger'].debug(log_messages['saving_state'].format(
            next_run=next_run))
    if not daemon:
        config['db'].set_last_sync(src=src, dest=dest,
                                   direction='edge2crits', timestamp=now)
        return(None)
    else:
        return(util_.nowutc())






    #             # check whether this observable resolves a crits
    #             # indicator relationship...
    #             doc = \
    #                 config['db'].get_pending_crits_link(src,
    #                                                     dest,
    #                                                     edge_id=stix_id)
    #             if doc:
    #                 if doc.get('crits_indicator_id', None):
    #                     resolved_relationship_blob = dict()
    #                     resolved_relationship_blob['stix_id'] = stix_id
    #                     resolved_relationship_blob['left_type'] = 'Indicator'
    #                     resolved_relationship_blob['left_id'] = \
    #                         doc['crits_indicator_id']
    #                     resolved_relationship_blob['right_type'] = \
    #                         endpoint_trans[endpoint]
    #                     resolved_relationship_blob['right_id'] = id_
    #                     resolved_relationship_blob['rel_type'] = 'Contains'
    #                     resolved_relationship_blob['rel_confidence'] = \
    #                         'unknown'
    #                     resolved_crits_relationships.append(
    #                         resolved_relationship_blob)
    # # generate json for indicators (must be after observables because
    # # we need to know what id crits assigned for related observables)
    # for i in indicators.keys():
    #     (indicator_json, relationships_json, unresolvables) = \
    #         stix_ind2json(config, src, dest,
    #                       indicators[i], observable_compositions,
    #                       problem_children)
    #     if unresolvables:
    #         unresolvables_dict[indicator_json['stix_id']] = unresolvables
    #     if indicator_json:
    #         # mark crits releasability...
    #         indicator_json.update(mark_crits_releasability(config, src))
    #         json_['indicators'][i] = indicator_json
    #     else:
    #         config['logger'].error('indicator %s stix could not be converted '
    #                                'to crits json!' % str(i))
    #     if relationships_json:
    #         # mark crits releasability...
    #         relationships_json.update(mark_crits_releasability(config, src))
    #         json_['relationships'][i] = relationships_json
    #     else:
    #         config['logger'].error('indicator %s stix could not be converted '
    #                                'to crits json!' % str(i))
    # # sync indicators...


# observable_compositions = dict()
# elif util_.rgetattr(observable, ['observable_composition',
#                                  'observables']):
#     observable_compositions[observable.id_] = observable
# else:
#     config['logger'].error('observable %s stix could not '
#                            'be converted to crits json!'
#                            % str(observable.id_))
