#!/usr/bin/env python2.7

from copy import deepcopy
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.file_object import File
from cybox.objects.email_message_object import EmailMessage, EmailHeader
from cybox.utils import Namespace
from cybox.common import Hash
from cybox.utils import set_id_namespace as set_cybox_id_namespace
from libtaxii.constants import *
from stix.core import STIXPackage, STIXHeader
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.indicator import Indicator
from stix.utils import set_id_namespace as set_stix_id_namespace
import util_ #import nowutcmin, epoch_start, rgetattr
import log_
import StringIO
import crits_
import libtaxii as t
import libtaxii.clients as tc
import libtaxii.messages_10 as tm10
import libtaxii.messages_11 as tm11
import lxml.etree
import pytz
import yaml
import datetime


# TODO support proxies
# TODO support certificate auth
# TODO add more granular error checks
# TODO take taxii version from config and use the corresponding api
# TODO for some reason crits isn't accepting anything but md5 via the
#      api o_O
# TODO batch this up similarly to how crits-to-stix works (a la, 100x
#      observables at a time or similar)
# TODO need to avoid syncing when new data on one side is new
#      precisely because it was just injected from the other side
# TODO need to fix timestamps so they match the original data
# TODO need to set the xmlns to show the origin (aka,
#      demo_site_a_crits: https://54.154.28.239)
# TODO how to handle updates???


def stix2json(config, observable):
    if isinstance(observable.object_.properties, Address):
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
                return(json, endpoint)
    elif isinstance(observable.object_.properties, DomainName):
        crits_types = {'FQDN': 'A'}
        # crits doesn't appear to support tlds...
        endpoint = 'domains'
        domain_category = util_.rgetattr(observable.object_.properties, ['type_'])
        domain_value = util_.rgetattr(observable.object_.properties, ['value', 'value'])
        if domain_category and domain_value:
            json = {'domain': domain_value, 'type': crits_types[domain_category]}
            return(json, endpoint)
    elif isinstance(observable.object_.properties, File):
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
        return(json, endpoint)
    elif isinstance(observable.object_.properties, EmailMessage):
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
            json['from_'] = from_
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
        # import pudb; pu.db
        # for key in crits_types.keys():
        #     try:
        #         val = observable.object_.properties.header.__get_attr__(key)
        #     except AttributeError:
        #         val = None
        #     if val:
        #         json[crits_types[key]] = val
        # print(json)
        return(json, endpoint)
    else:
        config['logger'].error('unsupported stix object type %s!' % type(observable.object_.properties))
        endpoint = None
        return(None, endpoint)

        
def taxii_poll(config, target, timestamp=None):
    '''pull stix from edge via taxii'''
    client = tc.HttpClient()
    client.setUseHttps(config['edge']['sites'][target]['taxii']['ssl'])
    client.setAuthType(client.AUTH_BASIC)
    client.setAuthCredentials({'username': config['edge']['sites'][target]['taxii']['user'], \
                               'password': config['edge']['sites'][target]['taxii']['pass']})
    if not timestamp:
        earliest = util_.epoch_start()
    else:
        earliest = timestamp
    latest = util_.nowutcmin()
    poll_request = tm10.PollRequest(
                message_id=tm10.generate_message_id(),
                feed_name=config['edge']['sites'][target]['taxii']['collection'],
                exclusive_begin_timestamp_label=earliest,
                inclusive_end_timestamp_label=latest,
                content_bindings=[t.CB_STIX_XML_11])
    http_response = client.callTaxiiService2(config['edge']['sites'][target]['host'], config['edge']['sites'][target]['taxii']['path'], t.VID_TAXII_XML_10, poll_request.to_xml(), port=config['edge']['sites'][target]['taxii']['port'])
    taxii_message = t.get_message_from_http_response(http_response, poll_request.message_id)
    json_list = None
    if isinstance(taxii_message, tm10.StatusMessage):
        config['logger'].error('unhandled taxii polling error! (%s)' % taxii_message.message)
    elif isinstance(taxii_message, tm10.PollResponse):
        endpoints = ['ips', 'domains', 'samples', 'emails']
        json_ = dict()
        for endpoint in endpoints:
            json_[endpoint] = list()
        # TODO use a generator here...
        for content_block in taxii_message.content_blocks:
            xml = StringIO.StringIO(content_block.content)
            stix_package = STIXPackage.from_xml(xml)
            xml.close()
            if stix_package.observables:
                for observable in stix_package.observables.observables:
                    (json, endpoint) = stix2json(config, observable)
                    if json:
                        # mark crits releasability...
                        # json['releasability'] = [{'name': config['crits']['sites'][target]['api']['source'], 'analyst': 'toor', 'instances': []},]
                        # json['c-releasability.name'] = config['crits']['sites'][target]['api']['source']
                        # json['releasability.name'] = config['crits']['sites'][target]['api']['source']
                        json_[endpoint].append(json)
                    else:
                        config['logger'].error('observable %s stix could not be converted to crits json!' % str(observable.id_))
        return(json_, latest)


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


def edge2crits(config, source, destination, daemon=False):
    # check if (and when) we synced source and destination...
    state_key = source + '_to_' + destination
    now = util_.nowutcmin()
    # make yaml play nice...
    if not isinstance(config['state'], dict):
        config['state'] = dict()
    if not state_key in config['state'].keys():
        config['state'][state_key] = dict()
    if not 'edge_to_crits' in config['state'][state_key].keys():
        config['state'][state_key]['edge_to_crits'] = dict()
    if 'timestamp' in config['state'][state_key]['edge_to_crits'].keys():
        timestamp = config['state'][state_key]['edge_to_crits']['timestamp'].replace(tzinfo=pytz.utc)
        config['logger'].info('syncing new crits data since %s between %s and %s' % (str(timestamp), source, destination))
    else:
        config['logger'].info('initial sync between %s and %s' % (source, destination))
        # looks like first sync...
        # ...so we'll want to poll all records...
        timestamp = util_.epoch_start()
    (json_, latest) = taxii_poll(config, source, timestamp)
    total_input = 0
    total_output = 0
    subtotal_input = {}
    subtotal_output = {}
    for endpoint in json_.keys():
        subtotal_input[endpoint] = 0
        subtotal_output[endpoint] = 0
        for blob in json_[endpoint]:
            total_input += 1
            subtotal_input[endpoint] += 1
    config['logger'].info('%i (total) objects to be synced between %s (edge) and %s (crits)' % (total_input, source, destination))
    for endpoint in json_.keys():
        config['logger'].info('%i %s objects to be synced between %s (edge) and %s (crits)' % (subtotal_input[endpoint], endpoint, source, destination))
        for blob in json_[endpoint]:
            (id_, success) = crits_.crits_inbox(config, destination, endpoint, blob)
            if not success:
                config['logger'].error('%s object with id %s could not be synced from %s (edge) to %s (crits)!' % (endpoint, str(id_), source, destination))
            else:
                if config['daemon']['debug']:
                    config['logger'].debug('%s object with id %s was synced from %s (edge) to %s (crits)' % (endpoint, str(id_), source, destination))
                subtotal_output[endpoint] += 1
                total_output += 1
        config['logger'].info('%i %s objects successfully synced between %s (edge) and %s (crits)' % (subtotal_output[endpoint], endpoint, source, destination))
        if subtotal_output[endpoint] < subtotal_input[endpoint]:
            config['logger'].info('%i %s objects could not be synced between %s (edge) and %s (crits)' % (subtotal_input[endpoint] - subtotal_output[endpoint], endpoint, source, destination))
    config['logger'].info('%i (total) objects successfully synced between %s (edge) and %s (crits)' % (total_output, source, destination))
    if total_output < total_input:
        config['logger'].info('%i (total) objects could not be synced between %s (edge) and %s (crits)' % (total_input - total_output, source, destination))
    # save state to disk for next run...
    if config['daemon']['debug']:
        config['logger'].debug('saving state until next run [%s]' % str(latest + datetime.timedelta(seconds=config['edge']['sites'][source]['taxii']['poll_interval'])))
    if not daemon:
        yaml_ = deepcopy(config)
        yaml_['state'][state_key]['edge_to_crits']['timestamp'] = latest
        del yaml_['config_file']
        del yaml_['logger']
        file_ = file(config['config_file'], 'w')
        yaml.dump(yaml_, file_, default_flow_style=False)
        file_.close()
    else:
        config['state'][state_key]['edge_to_crits']['timestamp'] = latest
