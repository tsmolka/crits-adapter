#!/usr/bin/env python2.7

from copy import deepcopy
from cybox.common import Hash
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
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


def cybox2json(config, observable):    
    props = util_.rgetattr(observable.object_, ['properties'])
    if props and isinstance(props, Address):
        crits_types = {'cidr'         : 'Address - cidr', \
                       'ipv4-addr'    : 'Address - ipv4-addr', \
                       'ipv4-net'     : 'Address - ipv4-net', \
                       'ipv4-netmask' : 'Address - ipv4-net-mask', \
                       'ipv6-addr'    : 'Address - ipv6-addr', \
                       'ipv6-net'     : 'Address - ipv6-net', \
                       'ipv6-netmask' : 'Address - ipv6-net-mask'}
        endpoint = 'ips'
        condition = util_.rgetattr(observable.object_.properties, ['condition'])
        if condition == 'Equals':
            # currently not handling other observable conditions as
            # it's not clear that crits even supports these...
            ip_category = util_.rgetattr(observable.object_.properties, ['category'])
            ip_value = util_.rgetattr(observable.object_.properties, ['address_value', 'value'])
            if ip_value and ip_category:
                json = {'ip': ip_value, 'ip_type': crits_types[ip_category]}
                # hash_ = util_.dicthash_sha1(json)
                # json['_id'] = hash_
                json['stix_id'] = observable.id_
                return(json, endpoint)
    elif props and isinstance(props, DomainName):
        crits_types = {'FQDN': 'A'}
        # crits doesn't appear to support tlds...
        endpoint = 'domains'
        domain_category = util_.rgetattr(observable.object_.properties, ['type_'])
        domain_value = util_.rgetattr(observable.object_.properties, ['value', 'value'])
        if domain_category and domain_value:
            json = {'domain': domain_value, 'type': crits_types[domain_category]}
            # hash_ = util_.dicthash_sha1(json)
            # json['_id'] = hash_
            json['stix_id'] = observable.id_
            return(json, endpoint)
    elif props and isinstance(props, File):
        crits_types = {'MD5'    : 'md5', \
                       'SHA1'   : 'sha1', \
                       'SHA224' : 'sha224', \
                       'SHA256' : 'sha256', \
                       'SHA384' : 'sha384', \
                       'SHA512' : 'sha512', \
                       'SSDEEP' : 'ssdeep'}
        endpoint = 'samples'
        json = {'upload_type': 'metadata'}
        hashes = util_.rgetattr(observable.object_.properties, ['hashes'])
        if hashes:
            for hash in hashes:
                hash_type = util_.rgetattr(hash, ['type_', 'value'])
                hash_value = util_.rgetattr(hash, ['simple_hash_value', 'value'])
                if hash_type and hash_value:
                    json[crits_types[hash_type]] = hash_value
        file_name = util_.rgetattr(observable.object_.properties, ['file_name', 'value'])
        if file_name:
            json['filename'] = file_name
        file_format = util_.rgetattr(observable.object_.properties, ['file_format', 'value'])
        if file_format:
            json['filetype'] = file_format
        file_size = util_.rgetattr(observable.object_.properties, ['size_in_bytes', 'value'])
        if file_size:
            json['size'] = file_size
        # hash_ = util_.dicthash_sha1(json)
        # json['_id'] = hash_
        json['stix_id'] = observable.id_
        return(json, endpoint)
    elif props and isinstance(props, EmailMessage):
        crits_types = {'subject': 'subject', 'to': 'to', 'cc': 'cc',
        'from_': 'from_address', 'sender': 'sender', 'date': 'date',
        'message_id': 'message_id', 'reply_to': 'reply_to',
        'boundary': 'boundary', 'x_mailer': 'x_mailer',
        'x_originating_ip': 'x_originating_ip'}
        json = {'upload_type': 'fields'}
        endpoint = 'emails'
        subject = util_.rgetattr(observable.object_.properties, ['header', 'subject', 'value'])
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
        from_ = util_.rgetattr(observable.object_.properties, ['header', 'from_', 'address_value', 'value'])
        if from_:
            json['from_address'] = [from_,]
        sender = util_.rgetattr(observable.object_.properties, ['header', 'sender', 'address_value', 'value'])
        if sender:
            json['sender'] = sender
        date = util_.rgetattr(observable.object_.properties, ['header', 'date', 'value'])
        if date:
            json['date'] = date
        message_id = util_.rgetattr(observable.object_.properties, ['header', 'message_id', 'value'])
        if message_id:
            json['message_id'] = message_id
        reply_to = util_.rgetattr(observable.object_.properties, ['header', 'reply_to', 'address_value', 'value'])
        if reply_to:
            json['reply_to'] = reply_to
        boundary = util_.rgetattr(observable.object_.properties, ['header', 'boundary', 'value'])
        if boundary:
            json['boundary'] = boundary
        x_mailer = util_.rgetattr(observable.object_.properties, ['header', 'x_mailer', 'value'])
        if x_mailer:
            json['x_mailer'] = x_mailer
        x_originating_ip = util_.rgetattr(observable.object_.properties, ['header', 'x_originating_ip', 'value'])
        if x_originating_ip:
            json['x_originating_ip'] = x_originating_ip
        # for key in crits_types.keys():
        #     try:
        #         val = observable.object_.properties.header.__get_attr__(key)
        #     except AttributeError:
        #         val = None
        #     if val:
        #         json[crits_types[key]] = val
        # print(json)

        # hash_ = util_.dicthash_sha1(json)
        # json['_id'] = hash_
        json['stix_id'] = observable.id_
        return(json, endpoint)
    else:
        config['logger'].error('unsupported stix object type %s!' % type(props))
        endpoint = None
        return(None, endpoint)


def stix_ind2json(config, source, destination, indicator, observable_compositions):
    endpoint_trans = {'emails': 'Email', 'ips': 'IP', 'samples': 'Sample' , 'domains': 'Domain'}
    indicator_json = dict()
    relationship_json = list()
    indicator_json['stix_id'] = indicator.id_
    indicator_json['type'] = 'Reference'
    indicator_json['value'] = util_.rgetattr(indicator, ['title'])
    indicator_json['indicator_confidence'] = util_.rgetattr(indicator, ['confidence', 'value', 'value'])
    # TODO lookup the corresponding stix prop for indicator_impact
    indicator_json['indicator_impact'] = {'rating': 'unknown',}
    if util_.rgetattr(indicator, ['observables']):
        container_observable = indicator.observables[0]
        composite_observable_id = util_.rgetattr(container_observable, ['idref'])
        if not composite_observable_id:
            config['logger'].error('unable to deference observable composition for stix indicator %s!' % indicator.id_)
            return(None, None)
        composite_observable = observable_compositions.get(composite_observable_id, None)
        if not composite_observable:
            config['logger'].error('unable to deference observable composition for stix indicator %s!' % indicator.id_)
            return(None, None)
        observables_list = util_.rgetattr(composite_observable, ['observable_composition', 'observables'])
        if not observables_list:
            config['logger'].error('unable to deference observable composition for stix indicator %s!' % indicator.id_)
            return(None, None)
        # import pudb; pu.db
        for i in observables_list:
            blob = dict()
            blob['left_type'] = 'Indicator'
            blob['left_id'] = None
            rhs = config['db'].get_object_id(source, destination, edge_id=i.idref)
            if not rhs:
                config['logger'].error('unable to deference observable composition for stix indicator %s!' % indicator.id_)
                return(None, None)
            if not rhs.get('crits_id', None):
                config['logger'].error('unable to deference observable composition for stix indicator %s!' % indicator.id_)
                return(None, None)
            blob['right_type'] = endpoint_trans[rhs['crits_id'].split(':')[0]]
            blob['right_id'] = rhs['crits_id'].split(':')[1]
            blob['rel_type'] = 'Contains'
            blob['rel_confidence'] = 'unknown'
            relationship_json.append(blob)
    return(indicator_json, relationship_json)

    
def taxii_poll(config, source, destination, timestamp=None):
    '''pull stix from edge via taxii'''
    client = tc.HttpClient()
    client.setUseHttps(config['edge']['sites'][source]['taxii']['ssl'])
    client.setAuthType(client.AUTH_BASIC)
    client.setAuthCredentials({'username': config['edge']['sites'][source]['taxii']['user'], \
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
    http_response = client.callTaxiiService2(config['edge']['sites'][source]['host'], config['edge']['sites'][source]['taxii']['path'], t.VID_TAXII_XML_10, poll_request.to_xml(), port=config['edge']['sites'][source]['taxii']['port'])
    taxii_message = t.get_message_from_http_response(http_response, poll_request.message_id)
    json_list = None
    if isinstance(taxii_message, tm10.StatusMessage):
        config['logger'].error('unhandled taxii polling error! (%s)' % taxii_message.message)
    elif isinstance(taxii_message, tm10.PollResponse):
        endpoints = ['ips', 'domains', 'samples', 'emails', 'indicators', 'relationships']
        json_ = dict()
        for endpoint in endpoints:
            json_[endpoint] = list()
            json_['indicators'] = dict()
            json_['relationships'] = dict()
        # TODO use a generator here...
        observable_compositions = dict()
        indicators = dict()
        for content_block in taxii_message.content_blocks:
            xml = StringIO.StringIO(content_block.content)
            stix_package = STIXPackage.from_xml(xml)
            xml.close()
            if stix_package.observables:
                for observable in stix_package.observables.observables:
                    if util_.rgetattr(observable, ['object_']):
                        (json, endpoint) = cybox2json(config, observable)
                        if json:
                            # mark crits releasability...
                            # json['releasability'] = [{'name': config['crits']['sites'][source]['api']['source'], 'analyst': 'toor', 'instances': []},]
                            # json['c-releasability.name'] = config['crits']['sites'][source]['api']['source']
                            # json['releasability.name'] = config['crits']['sites'][source]['api']['source']
                            json_[endpoint].append(json)
                        else:
                            config['logger'].error('observable %s stix could not be converted to crits json!' % str(observable.id_))
                    elif util_.rgetattr(observable, ['observable_composition', 'observables']):
                        observable_compositions[observable.id_] = observable
                    else:
                        config['logger'].error('observable %s stix could not be converted to crits json!' % str(observable.id_))
            if stix_package.indicators:
                for i in stix_package.indicators:
                    indicators[i.id_] = i
        return(json_, latest, indicators, observable_compositions)


def taxii_inbox(config, target, stix_package=None):
    if stix_package:
        stixroot = lxml.etree.fromstring(stix_package.to_xml())
        client = tc.HttpClient()
        client.setUseHttps(config['edge']['sites'][target]['taxii']['ssl'])
        client.setAuthType(client.AUTH_BASIC)
        client.setAuthCredentials({'username': config['edge']['sites'][target]['taxii']['user'], 'password': config['edge']['sites'][target]['taxii']['pass']})
        message = tm11.InboxMessage(message_id=tm11.generate_message_id())
        content_block = tm11.ContentBlock(
            content_binding = t.CB_STIX_XML_11, # of _101, _11, _111
            content         = stixroot,
        )
        if config['edge']['sites'][target]['taxii']['collection'] != 'system.Default':
            message.destination_collection_names = [config['edge']['sites'][target]['taxii']['collection'],]
        message.content_blocks.append(content_block)
        if config['daemon']['debug']:
            config['logger'].debug('initiating taxii connection to %s' % target)
        taxii_response = client.callTaxiiService2(config['edge']['sites'][target]['host'], config['edge']['sites'][target]['taxii']['path'], t.VID_TAXII_XML_11, message.to_xml(), port=config['edge']['sites'][target]['taxii']['port'])
        if taxii_response.code != 200 or taxii_response.msg != 'OK':
            success = False
            config['logger'].error('taxii inboxing to %s failed! [%s]' % (target, taxii_response.msg))
        else:
            success = True
            if config['daemon']['debug']:
                config['logger'].debug('taxii inboxing to %s was successful' % target)
        return(success)


def edge2crits(config, source, destination, daemon=False, now=None, last_run=None):
    # import pudb; pu.db
    observable_endpoints = ['ips', 'domains', 'samples', 'emails']
    # check if (and when) we synced source and destination...
    if not now:
        now = util_.nowutc()
    if not last_run:
        last_run = config['db'].get_last_sync(source=source, destination=destination, direction='edge2crits').replace(tzinfo=pytz.utc)
    config['logger'].info('syncing new edge data since %s between %s and %s' % (str(last_run), source, destination))
    (json_, latest, indicators, observable_compositions) = taxii_poll(config, source, destination, last_run)
    total_input = 0
    total_output = 0
    subtotal_input = {}
    subtotal_output = {}
    subtotal_input['indicators'] = 0
    subtotal_output['indicators'] = 0
    for endpoint in observable_endpoints:
        subtotal_input[endpoint] = 0
        subtotal_output[endpoint] = 0
        for blob in json_[endpoint]:
            sync_state = config['db'].get_object_id(source, destination, edge_id=blob['stix_id'])
            if sync_state:
                if sync_state.get('crits_id', None):
                    if config['daemon']['debug']:
                        config['logger'].debug('edge object id %s already in system' % blob['stix_id'])
                        json_[endpoint].remove(blob)
                else:
                    total_input += 1
                    subtotal_input[endpoint] += 1
    for i in json_['indicators'].keys():
        sync_state = config['db'].get_object_id(source, destination, edge_id=json_['indicators'][i]['stix_id'])
        if sync_state:
            if sync_state.get('crits_id', None):
                if config['daemon']['debug']:
                    config['logger'].debug('edge object id %s already in system' % blob['stix_id'])
                    del json_['indicators'][i]
            else:
                total_input += 1
                subtotal_input['indicators'] += 1
    if total_input > 0:
        config['logger'].info('%i (total) objects to be synced between %s (edge) and %s (crits)' % (total_input, source, destination))
    for endpoint in observable_endpoints:
        if subtotal_input[endpoint] > 0:
            config['logger'].info('%i %s objects to be synced between %s (edge) and %s (crits)' % (subtotal_input[endpoint], endpoint, source, destination))
        for blob in json_[endpoint]:
            stix_id = blob['stix_id']
            del blob['stix_id']
            (id_, success) = crits_.crits_inbox(config, destination, endpoint, blob)
            if not success:
                config['logger'].error('%s object with id %s could not be synced from %s (edge) to %s (crits)!' % (endpoint, str(stix_id), source, destination))
            else:
                if config['daemon']['debug']:
                    config['logger'].debug('%s object with id %s was synced from %s (edge) to %s (crits)' % (endpoint, str(stix_id), source, destination))
                config['db'].set_object_id(source, destination, edge_id=stix_id, crits_id=endpoint + ':' + str(id_), timestamp=util_.nowutc())
                subtotal_output[endpoint] += 1
                total_output += 1
        if subtotal_output[endpoint] > 0:
            config['logger'].info('%i %s objects successfully synced between %s (edge) and %s (crits)' % (subtotal_output[endpoint], endpoint, source, destination))
        if subtotal_output[endpoint] < subtotal_input[endpoint]:
            config['logger'].info('%i %s objects could not be synced between %s (edge) and %s (crits)' % (subtotal_input[endpoint] - subtotal_output[endpoint], endpoint, source, destination))
        # indicators
        for i in indicators.keys():
            (indicator_json, relationships_json) = stix_ind2json(config, source, destination, indicators[i], observable_compositions)
            if indicator_json:
                # mark crits releasability...
                # indicator_json['releasability'] = [{'name': config['crits']['sites'][source]['api']['source'], 'analyst': 'toor', 'instances': []},]
                # indicator_json['c-releasability.name'] = config['crits']['sites'][source]['api']['source']
                # indicator_json['releasability.name'] = config['crits']['sites'][source]['api']['source']
                json_['indicators'][i] = indicator_json
            else:
                config['logger'].error('indicator %s stix could not be converted to crits json!' % str(i))
            if relationships_json:
                # mark crits releasability...
                # relationship_json['releasability'] = [{'name': config['crits']['sites'][source]['api']['source'], 'analyst': 'toor', 'instances': []},]
                # relationship_json['c-releasability.name'] = config['crits']['sites'][source]['api']['source']
                # relationship_json['releasability.name'] = config['crits']['sites'][source]['api']['source']
                json_['relationships'][i] = relationships_json
            else:
                config['logger'].error('indicator %s stix could not be converted to crits json!' % str(i))
        for i in json_['indicators'].keys():
            stix_id = json_['indicators'][i]['stix_id']
            del json_['indicators'][i]['stix_id']
            (id_, success) = crits_.crits_inbox(config, destination, 'indicators', json_['indicators'][i])
            if not success:
                config['logger'].error('%s object with id %s could not be synced from %s (edge) to %s (crits)!' % ('indicators', str(stix_id), source, destination))
            else:
                if config['daemon']['debug']:
                    config['logger'].debug('%s object with id %s was synced from %s (edge) to %s (crits)' % ('indicators', str(stix_id), source, destination))
            # import pudb; pu.db
            for blob in json_['relationships'][i]:
                blob['left_id'] = id_
                (relationship_id_, success) = crits_.crits_inbox(config, destination, 'relationships', blob)
                if not success:
                    config['logger'].error('unable to create crits indicator relationship %s (id %s) for crits indicator id %s!' % (blob['right_type'], blob['right_id'], id_))
            config['db'].set_object_id(source, destination, edge_id=stix_id, crits_id='indicators:%s' % str(id_), timestamp=util_.nowutc())
            subtotal_output['indicators'] += 1
            total_output += 1
        if subtotal_output['indicators'] > 0:
            config['logger'].info('%i %s objects successfully synced between %s (edge) and %s (crits)' % (subtotal_output['indicators'], 'indicators', source, destination))
        if subtotal_output['indicators'] < subtotal_input['indicators']:
            config['logger'].info('%i %s objects could not be synced between %s (edge) and %s (crits)' % (subtotal_input['indicators'] - subtotal_output['indicators'], 'indicators', source, destination))
    if total_output > 0:
        config['logger'].info('%i (total) objects successfully synced between %s (edge) and %s (crits)' % (total_output, source, destination))
    if total_output < total_input:
        config['logger'].info('%i (total) objects could not be synced between %s (edge) and %s (crits)' % (total_input - total_output, source, destination))
    # save state to disk for next run...
    if config['daemon']['debug']:
        config['logger'].debug('saving state until next run [%s]' % str(now + datetime.timedelta(seconds=config['edge']['sites'][source]['taxii']['poll_interval'])))
    if not daemon:
        config['db'].set_last_sync(source=source, destination=destination, direction='edge2crits', timestamp=now)
        return(None)
    else:
        return(util_.nowutc())
