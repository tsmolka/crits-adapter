#!/usr/bin/env python

# TODO make imports modular based on cli args
# TODO add logging!!!
from stix.core import STIXPackage, STIXHeader
from stix.indicator import Indicator
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.utils import set_id_namespace as set_stix_id_namespace
from cybox.utils import Namespace
from cybox.utils import set_id_namespace as set_cybox_id_namespace
from cybox.objects.address_object import Address
from cybox.objects.file_object import File
from cybox.objects.domain_name_object import DomainName
import libtaxii as t
import libtaxii.clients as tc
import libtaxii.messages_11 as tm11
from libtaxii.constants import *
import libtaxii.messages_10 as tm10
import datetime
from dateutil.tz import tzutc
import StringIO
import sys
import lxml.etree
from random import randint
from struct import pack
from socket import inet_ntoa
from docopt import docopt
import yaml
import requests
import json
import uuid
import random
import time
import os.path
import pytz


__version__ = '0.1'
app_path = os.path.split(os.path.abspath(__file__))[0]
default_config = os.path.join(app_path, 'config.yaml')

__doc__ = '''edgy_crits.py: bidirectional synchronization between Soltra Edge and MITRE CRITs

Usage:
    edgy_crits.py [--config=CONFIG] --sync-crits-to-edge --source=SOURCE --destination=DESTINATION
    edgy_crits.py [--config=CONFIG] --sync-edge-to-crits --source=SOURCE --destination=DESTINATION

    edgy_crits.py --help
    edgy_crits.py --version


Options:
    -c CONFIG --config=CONFIG         Specify config file to use [default: %s].
    -h --help                         Show this screen.
    -V --version                      Show version.
    SOURCE...                         Specify host defined in config.yaml
    DESTINATION...                    Specify host defined in config.yaml

Please report bugs to support@soltra.com
''' % (default_config)


# shamelessly plundered from repository.edge.tools :-P
#
# recursive getattr()
# syntax is the same as getattr, but the requested
# attribute is a list instead of a string.
#
# e.g. confidence = rgetattr(apiobject,['confidence','value','value'])
#                 = apiobject.confidence.value.value
#
def rgetattr(object_ ,list_ ,default_=None):
    """recursive getattr using a list"""
    if object_ is None:
        return default_
    if len(list_) == 1:
        return getattr(object_, list_[0], default_)
    else:
        return rgetattr(getattr(object_, list_[0], None), list_[1:], default_)

    
def nowutcmin():
    """time now, but only minute-precision"""
    return datetime.datetime.utcnow().replace(second=0,microsecond=0).replace(tzinfo=pytz.utc)


def epoch_start():
    '''it was the best of times, it was the worst of times...'''
    return datetime.datetime.utcfromtimestamp(0).replace(tzinfo=pytz.utc)


def parse_config(file_):
    '''parse a yaml config file'''
    try:
        return(yaml.safe_load(file(file_, 'r')))
    except yaml.YAMLError:
        print('error parsing yaml file: %s; check your syntax!' % file_)
        exit()

        
def get_crits_api_base_url(config, target):
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


def pull_json_via_crits_api(config, target, endpoint, object_ids=None):
    '''pull data from crits via api, return json as a dict'''
    url = get_crits_api_base_url(config, target)
    results = dict()
    if config['crits']['sites'][target]['api']['allow_self_signed']:
        requests.packages.urllib3.disable_warnings()
    # import pudb; pu.db
    data = {'api_key'  : config['crits']['sites'][target]['api']['key'],
            'username' : config['crits']['sites'][target]['api']['user']}
    # import pudb; pu.db
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


def upload_json_via_crits_api(config, target, endpoint, json):
    '''upload data to crits via api, return object id if successful'''
    url = get_crits_api_base_url(config, target)
    if config['crits']['sites'][target]['api']['allow_self_signed']:
        requests.packages.urllib3.disable_warnings()
    # import pudb; pu.db
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


def cybox_to_crits_json(observable):
    if isinstance(observable.object_.properties, Address):
        crits_types = {'cidr'         : 'Address - cidr', \
                       'ipv4-addr'    : 'Address - ipv4-net', \
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
                # TODO for some reason crits isn't accepting anything
                #      but md5 via the api o_O
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
    # return(json, endpoint)

        
def pull_stix_via_taxii(config, target, timestamp=None):
    '''pull stix from edge via taxii'''
    client = tc.HttpClient()
    client.setUseHttps(config['edge']['sites'][target]['taxii']['ssl'])
    client.setAuthType(client.AUTH_BASIC)
    client.setAuthCredentials({'username': config['edge']['sites'][target]['taxii']['user'], \
                               'password': config['edge']['sites'][target]['taxii']['pass']})
    # discovery_request = tm11.DiscoveryRequest(tm11.generate_message_id())
    # discovery_xml = discovery_request.to_xml(pretty_print=True)

    # http_resp = client.call_taxii_service2(config['edge']['sites'][target]['host'], config['edge']['sites'][target]['taxii']['path'], VID_TAXII_XML_11, discovery_xml)
    # taxii_message = t.get_message_from_http_response(http_resp, discovery_request.message_id)
    # print taxii_message.to_xml(pretty_print=True)
    # print type(epoch_start())
    # print type(nowutcmin())
    # exit()
    if not timestamp:
        earliest = epoch_start()
    else:
        earliest = timestamp
    latest = nowutcmin()
    poll_request = tm10.PollRequest(
                message_id=tm10.generate_message_id(),
                # feed_name=config['edge']['sites'][target]['taxii']['collection'],
                feed_name='system.Default',
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
        # print("Got response. There are %s packages" % len(taxii_message.content_blocks))
        # import pudb; pu.db
        for content_block in taxii_message.content_blocks:
            xml = StringIO.StringIO(content_block.content)
            stix_package = STIXPackage.from_xml(xml)
            xml.close()
            # print stix_package._id
            # if stix_package.indicators:
            #     print 'indicators: ' + str(len(stix_package.indicators))
            if stix_package.observables:
                for observable in stix_package.observables.observables:
                    (json, endpoint) = cybox_to_crits_json(observable)
                    if json:
                        # mark crits releasability...
                        json['releasability'] = config['crits']['sites'][target]['api']['source']
                        # TODO batch this up similarly to how
                        #      crits-to-stix works (a la, 100x observables
                        #      at a time or similar)
                        json_[endpoint].append(json)
    return(json_, latest)
    # if http_response.code != 200 or http_response.msg != 'OK':
    #     success = False
    # else:
    #     success = True
    # return(success)



def upload_stix_via_taxii(config, target, stix_package=None):
    # TODO support proxies
    # TODO support certificate auth
    # TODO add more granular error checks
    # TODO take taxii version from config and use the corresponding 
   #      api
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
        message.destination_collection_names = [config['edge']['sites'][target]['taxii']['collection'],]
        # TODO need to avoid syncing when new data on one side is new
        #      precisely because it was just injected from the other
        #      side
        # TODO need to fix timestamps so they match the original data
        # TODO need to set the xmlns to show the origin (aka,
        #      demo_site_a_crits: https://54.154.28.239)
        message.content_blocks.append(content_block)
        taxii_response = client.callTaxiiService2(config['edge']['sites'][target]['host'], config['edge']['sites'][target]['taxii']['path'], t.VID_TAXII_XML_11, message.to_xml(), port=config['edge']['sites'][target]['taxii']['port'])
        if taxii_response.code != 200 or taxii_response.msg != 'OK':
            success = False
        else:
            success = True
        return(success)


def crits_to_stix(config, source, type_, json, title='random test data', description='random test data', package_intents='Indicators - Watchlist', tlp_color='WHITE'):
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
    for i in json.keys():
        indicator = Indicator(title='IP Address for known C2 Channel')
        indicator.add_indicator_type('IP Watchlist')
        addr = Address(address_value=json[i]['ip'], category=Address.CAT_IPV4)
        addr.condition = 'Equals'
        indicator.add_observable(addr)
        stix_package.add_indicator(indicator)
    return(stix_package)
        

def sync_crits_to_edge(config, source, destination):
    global config_file
    # TODO how to deal with deleted crits objects?
    # TODO ensure that both source and destination are actually defined!
    # 1. poll crits for objects created or modified since $timestamp
    # 2. check whether the crits object _id is present in edge
    # 3. transform each crits object into stix
    # 4. taxii inbox the stix into edge

    # check if (and when) we synced source and destination...
    state_key = source + '_to_' + destination
    now = nowutcmin() #datetime.datetime.now()
    # make yaml play nice...
    if not isinstance(config['state'], dict):
        config['state'] = dict()
    if not state_key in config['state'].keys():
        config['state'][state_key] = dict()
    if not 'crits_to_edge' in config['state'][state_key].keys():
        config['state'][state_key]['crits_to_edge'] = dict()
    if 'timestamp' in config['state'][state_key]['crits_to_edge'].keys():
        timestamp = config['state'][state_key]['crits_to_edge']['timestamp'].replace(tzinfo=pytz.utc)
    else:
        # looks like first sync...
        # ...so we'll want to poll all records...
        timestamp = None
    ids = fetch_crits_object_ids(config, source, 'ips', timestamp)
    upload_tracker = list(ids)
    if len(upload_tracker) > 100:
        while len(upload_tracker) > 100:
            outgoing_ids = upload_tracker[0:99]
            outgoing_json = pull_json_via_crits_api(config, source, 'ips', outgoing_ids)
            outgoing_stix = crits_to_stix(config, source, 'ips', outgoing_json)
            success = upload_stix_via_taxii(config, destination, outgoing_stix)
            if not success:
                print 'fail!!!'
                exit()
            else:
                upload_tracker = upload_tracker[100:]
    else:
        outgoing_json = pull_json_via_crits_api(config, source, 'ips', upload_tracker)
        outgoing_stix = crits_to_stix(config, source, 'ips', outgoing_json)
        # TODO if we fail midway through an operation, what should we
        #      do with the timestamp?
        # TODO ensure that all timestamps are utc!
        success = upload_stix_via_taxii(config, destination, outgoing_stix)
        if not success:
            print 'fail!!!'
            exit()
    # TODO how to handle updates???
    # save state to disk for next run...
    config['state'][state_key]['crits_to_edge']['timestamp'] = now
    file_ = file(config_file, 'w')
    yaml.dump(config, file_, default_flow_style=False)
    file_.close()


def sync_edge_to_crits(config, source, destination):
    global config_file
    # TODO ensure that both source and destination are actually defined!

    # 1. poll edge for objects created or modified since $timestamp
    # 2. check whether the stix _id is present in crits
    # 3. transform each stix object into crits json
    # 4. upload object via crits api

    # check if (and when) we synced source and destination...
    state_key = source + '_to_' + destination
    now = nowutcmin() # datetime.datetime.now()
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
    (json_, latest) = pull_stix_via_taxii(config, source, timestamp)
    # import pudb; pu.db
    for endpoint in json_.keys():
        for blob in json_[endpoint]:
            (id_, success) = upload_json_via_crits_api(config, destination, endpoint, blob)
    # ids = fetch_crits_object_ids(config, source, 'domains', timestamp)
    # TODO this will be a taxii operation of some kind...
    # pseudocode...
    # upload_tracker = list(ids)
    # for range of ids in ids:
    #     transform crits[id range] into stix package and inbox it...
    #     if upload is succesful, delete id range from upload_tracker
    #     TODO how to handle updates???
    # save state to disk for next run...
    config['state'][state_key]['edge_to_crits']['timestamp'] = latest
    file_ = file(config_file, 'w')
    yaml.dump(config, file_, default_flow_style=False)
    file_.close()



def __fetch_crits_object_ids(config, target, endpoint, params):
    '''fetch all crits object ids from endpoint and return a list'''
    url = get_crits_api_base_url(config, target)
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
    object_ids = set()
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
            object_ids.add(object_[u'_id'].encode('ascii', 'ignore'))
        i += 1
    return(object_ids)


def fetch_crits_object_ids(config, target, endpoint, timestamp=None):
    '''fetch all crits object ids from endpoint and return a list'''
    object_ids = set()
    if timestamp:
        crits_timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')
        # first, check for newly created records...
        params = {'api_key'        : config['crits']['sites'][target]['api']['key'],
                  'username'       : config['crits']['sites'][target]['api']['user'],
                  'limit'          : 1, # just grabbing meta for total object count...
                  'c-created__gt' : crits_timestamp,
                  'offset'         : 0}
        object_ids.update(__fetch_crits_object_ids(config, target, endpoint, params))
        # next, check for recently updated records...
        params = {'api_key'         : config['crits']['sites'][target]['api']['key'],
                  'username'        : config['crits']['sites'][target]['api']['user'],
                  'limit'           : 1, # just grabbing meta for total object count...
                  'c-modified__gt' : crits_timestamp,
                  'offset'          : 0}
        object_ids.update(__fetch_crits_object_ids(config, target, endpoint, params))
    else:
        params = {'api_key'  : config['crits']['sites'][target]['api']['key'],
                  'username' : config['crits']['sites'][target]['api']['user'],
                  'limit'    : 1, # just grabbing meta for total object count...
                  'offset'   : 0}
        object_ids.update(__fetch_crits_object_ids(config, target, endpoint, params))
    return(object_ids)


def main():
    args = docopt(__doc__, version=__version__)
    global config_file
    config_file = args['--config']
    config = parse_config(config_file)
    if args['--sync-crits-to-edge']:
        if args['--source'] in config['crits']['sites'].keys() and args['--destination'] in config['edge']['sites'].keys():
            sync_crits_to_edge(config, args['--source'], args['--destination'])
    elif args['--sync-edge-to-crits']:
        if args['--source'] in config['edge']['sites'].keys() and args['--destination'] in config['crits']['sites'].keys():
            sync_edge_to_crits(config, args['--source'], args['--destination'])
    # TODO track uploaded content and retrieve it via taxii poll...
    # TODO use certifi for urllib3 certificate validation :: https://urllib3.readthedocs.org/en/latest/security.html#certifi-with-urllib3


if __name__ == '__main__':
    main()





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


# 
# on polling default taxii feed with timestamp specification...
# 
# [7:22:37 PM] Trey Darley: hey, man, could you give me a pointed on querying the default with a timestamp range?
# [7:22:55 PM] benjamin yates: how are you sending PollRequests now?
# [7:23:05 PM] benjamin yates: custom stuff? libtaxii? taxiiexample?
# [7:23:15 PM] Trey Darley: libtaxii
# [7:24:16 PM] benjamin yates: in your PollRequest message, you can set

# request.exclusive_begin_timestamp_label

# and/or

# request.inclusive_end_timestamp_label
# [7:24:32 PM] benjamin yates: they are datetime+tz, with tz=utc
# [7:25:38 PM] benjamin yates: (your utc datetime).replace(tzinfo=dateuil.tz.tzutc())
# [7:25:52 PM] Trey Darley: cool, thanks!
# [7:26:14 PM] benjamin yates: you can find an example in

# /peers/client.py, line 514
# [7:27:27 PM] benjamin yates: and example usage of them serverside at

# taxii/streams11.py line 263
# [7:29:53 PM] Trey Darley: thanks, man
