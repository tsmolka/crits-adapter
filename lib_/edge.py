#!/usr/bin/env python

from copy import deepcopy
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.file_object import File
from cybox.utils import Namespace
from cybox.utils import set_id_namespace as set_cybox_id_namespace
from libtaxii.constants import *
from stix.core import STIXPackage, STIXHeader
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.indicator import Indicator
from stix.utils import set_id_namespace as set_stix_id_namespace
from util import nowutcmin, epoch_start, rgetattr
import StringIO
import crits
import libtaxii as t
import libtaxii.clients as tc
import libtaxii.messages_10 as tm10
import libtaxii.messages_11 as tm11
import lxml.etree
import pytz
import yaml


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


def stix2json(observable):
    if isinstance(observable.object_.properties, Address):
        crits_types = {'cidr'         : 'Address - cidr', \
                       'ipv4-addr'    : 'Address - ipv4-addr', \
                       'ipv4-net'     : 'Address - ipv4-net', \
                       'ipv4-netmask' : 'Address - ipv4-net-mask', \
                       'ipv6-addr'    : 'Address - ipv6-addr', \
                       'ipv6-net'     : 'Address - ipv6-net', \
                       'ipv6-netmask' : 'Address - ipv6-net-mask'}
        endpoint = 'ips'
        condition = rgetattr(observable.object_.properties, ['condition'])
        if condition == 'Equals':
            # currently not handling other observable conditions as
            # it's not clear that crits even supports these...
            ip_category = rgetattr(observable.object_.properties, ['category'])
            ip_value = rgetattr(observable.object_.properties, ['address_value', 'value'])
            if ip_value and ip_category:
                json = {'ip': ip_value, 'ip_type': crits_types[ip_category]}
                return(json, endpoint)
    elif isinstance(observable.object_.properties, DomainName):
        crits_types = {'FQDN': 'A'}
        # crits doesn't appear to support tlds...
        endpoint = 'domains'
        domain_category = rgetattr(observable.object_.properties, ['type_'])
        domain_value = rgetattr(observable.object_.properties, ['value', 'value'])
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
        hashes = rgetattr(observable.object_.properties, ['hashes'])
        if hashes:
            for hash in hashes:
                hash_type = rgetattr(hash, ['type_', 'value'])
                hash_value = rgetattr(hash, ['simple_hash_value', 'value'])
                if hash_type and hash_value:
                    json[crits_types[hash_type]] = hash_value
        file_name = rgetattr(observable.object_.properties, ['file_name', 'value'])
        if file_name:
            json['filename'] = file_name
        file_format = rgetattr(observable.object_.properties, ['file_format', 'value'])
        if file_format:
            json['filetype'] = file_format
        file_size = rgetattr(observable.object_.properties, ['size_in_bytes', 'value'])
        if file_size:
            json['size'] = file_size
        return(json, endpoint)
    else:
        import pudb; pu.db

        
def taxii_poll(config, target, timestamp=None):
    '''pull stix from edge via taxii'''
    client = tc.HttpClient()
    client.setUseHttps(config['edge']['sites'][target]['taxii']['ssl'])
    client.setAuthType(client.AUTH_BASIC)
    client.setAuthCredentials({'username': config['edge']['sites'][target]['taxii']['user'], \
                               'password': config['edge']['sites'][target]['taxii']['pass']})
    if not timestamp:
        earliest = epoch_start()
    else:
        earliest = timestamp
    latest = nowutcmin()
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
        print(taxii_message.message)
        exit()
    elif isinstance(taxii_message, tm10.PollResponse):
        json_ = {'ips': [], 'samples': [], 'emails': [], 'domains': []}
        for content_block in taxii_message.content_blocks:
            xml = StringIO.StringIO(content_block.content)
            stix_package = STIXPackage.from_xml(xml)
            xml.close()
            if stix_package.observables:
                for observable in stix_package.observables.observables:
                    (json, endpoint) = stix2json(observable)
                    if json:
                        # mark crits releasability...
                        # json['releasability'] = [{'name': config['crits']['sites'][target]['api']['source'], 'analyst': 'toor', 'instances': []},]
                        # json['c-releasability.name'] = config['crits']['sites'][target]['api']['source']
                        # json['releasability.name'] = config['crits']['sites'][target]['api']['source']
                        json_[endpoint].append(json)
    return(json_, latest)


def taxii_inbox(config, target, stix_package=None):
    # import pudb; pu.db
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
        taxii_response = client.callTaxiiService2(config['edge']['sites'][target]['host'], config['edge']['sites'][target]['taxii']['path'], t.VID_TAXII_XML_11, message.to_xml(), port=config['edge']['sites'][target]['taxii']['port'])
        if taxii_response.code != 200 or taxii_response.msg != 'OK':
            success = False
        else:
            success = True
        return(success)


def edge2crits(config, source, destination):
    # check if (and when) we synced source and destination...
    state_key = source + '_to_' + destination
    now = nowutcmin()
    # make yaml play nice...
    if not isinstance(config['state'], dict):
        config['state'] = dict()
    if not state_key in config['state'].keys():
        config['state'][state_key] = dict()
    if not 'edge_to_crits' in config['state'][state_key].keys():
        config['state'][state_key]['edge_to_crits'] = dict()
    if 'timestamp' in config['state'][state_key]['edge_to_crits'].keys():
        timestamp = config['state'][state_key]['edge_to_crits']['timestamp'].replace(tzinfo=pytz.utc)
    else:
        # looks like first sync...
        # ...so we'll want to poll all records...
        timestamp = epoch_start()
    (json_, latest) = taxii_poll(config, source, timestamp)
    for endpoint in json_.keys():
        for blob in json_[endpoint]:
            (id_, success) = crits.crits_inbox(config, destination, endpoint, blob)
    # save state to disk for next run...
    yaml_ = deepcopy(config)
    yaml_['state'][state_key]['edge_to_crits']['timestamp'] = latest
    del yaml_['config_file']
    file_ = file(config['config_file'], 'w')
    yaml.dump(yaml_, file_, default_flow_style=False)
    file_.close()
